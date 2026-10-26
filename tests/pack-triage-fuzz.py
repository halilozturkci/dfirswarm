#!/usr/bin/env python3
"""Structure-aware fuzz of the triage-collection manifest tools and the collection-intake recipe.

    fuzz.py --pack DIR --cases 1000 --seed 1 --work DIR [--tools parse,verify,path_map,coverage,recipe] [--out report.json]

One collection is generated per case from the formats' own definitions (KAPE copy/skip/console logs, UAC log and hash lists,
Velociraptor container files), with a ground truth kept beside it, then damaged: wrong sizes and digests, missing / unexpected /
case-twin / link / FIFO / unreadable files, credential-store names whose digests are canaries, broken CSV and JSON Lines, an
unlistable directory. Each tool then runs on the case (the same 1,000 collections for every tool, the arguments random per tool).
The recipe runs on the same tree packed as zip / tar / tgz / tbz2 / txz, sometimes cut, joined to a second archive, or holding a
nested archive. The oracles: the answer is JSON, no traceback, in time; no digest of a credential-store file (measured or claimed)
is in any output; an independent model of the join says what verify must report for the plain KAPE rows; an incomplete census never
says absent; the tools agree with each other (unexpected / candidate / without-a-record); the recipe agrees with the verify tool on
the same tree and is never complete for a tar that is cut.
"""
import argparse, bz2, csv, gzip, hashlib, io, json, lzma, os, random, re, shutil, subprocess, sys, tarfile, time, zipfile

SELF_UID = os.getuid()
CRED_NAMES = ["Windows/System32/config/SAM", "Windows/System32/config/SECURITY", "etc/shadow", "Users/a/.ssh/id_rsa", "etc/gshadow"]
PLAIN_NAMES = ["Windows/System32/config/SYSTEM", "Windows/a.txt", "Users/a/NTUSER.DAT", "Users/a/notes.txt", "Temp/x.bin", "Windows/Prefetch/CMD.EXE-1.pf", "Users/b/Doc 1.docx", "Windows/f.log", "var/log/auth.log", "home/u/.bash_history"]


def sha(alg, b):
    return hashlib.new(alg, b).hexdigest()


EMPTY = {sha(a, b"") for a in ("sha1", "sha256", "md5")}


class Case:
    def __init__(self, rng, base):
        self.rng, self.base = rng, base
        self.canaries = []          # digests of credential files, measured and claimed
        self.files = {}             # rel (under inputs/c) -> {"data":..., "cred": bool, "kind":"f"/"l"/"p"/"x"}
        self.census_incomplete = False
        self.unreadable_dir = None
        self.collectors = []

    def put(self, rel, data, cred=False):
        path = os.path.join(self.base, "inputs", "c", rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        self.files[rel] = {"data": data, "cred": cred, "kind": "f"}
        if cred:
            self.canaries += [sha("sha1", data), sha("sha256", data), sha("md5", data)]


def rdata(rng, n=None, cred=False):
    n = rng.choice([0, 1, 5, 50, 300, 2000, 70000]) if n is None else n
    body = bytes(rng.getrandbits(8) for _ in range(min(n, 4000))) + (b"\0" * max(0, n - 4000))
    # a credential file's bytes are unique to it, so its digests cannot be another file's
    return (b"CRED-%016x-" % rng.getrandbits(64)) + body if cred else body


def csv_text(rows, header):
    b = io.StringIO()
    w = csv.writer(b, lineterminator="\r\n")
    w.writerow(header)
    for r in rows:
        w.writerow(r)
    return b.getvalue()


KAPE_HEADER = ["CopiedTimestamp", "SourceFile", "DestinationFile", "FileSize", "SourceFileSha1", "DeferredCopy", "CreatedOnUtc", "ModifiedOnUtc", "LastAccessedOnUtc", "CopyDuration"]


def win(rel):
    return "C:\\" + rel.replace("/", "\\")


def gen_kape(case, rng, run):
    """A KAPE run directory `run` under inputs/c with a copy log, maybe a skip log and a console log."""
    names = rng.sample(PLAIN_NAMES, rng.randint(1, 6)) + rng.sample(CRED_NAMES, rng.randint(0, 3))
    rows, model = [], []
    for name in names:
        rel = name
        cred = name in CRED_NAMES
        data = rdata(rng, cred=cred)
        mode = rng.choices(["normal", "weak", "nofile", "wrong_size", "wrong_hash", "no_claims", "badsize", "upper", "linkat", "fifoat", "dup"], [40, 5, 8, 6, 6, 4, 3, 5, 3, 2, 3])[0]
        dest = "D:\\out\\C\\" + rel.replace("/", "\\")
        placed = os.path.join(run, "C", rel)
        if mode == "weak":
            placed = os.path.join(run, os.path.basename(rel))
        path_rel = placed
        claim_sha = sha("sha1", data)
        size_claim = str(len(data))
        if mode == "wrong_size":
            size_claim = str(len(data) + rng.randint(1, 9))
        if mode == "wrong_hash":
            claim_sha = "".join(rng.choice("0123456789abcdef") for _ in range(40))
            if cred:
                case.canaries.append(claim_sha)
        if mode == "no_claims":
            size_claim, claim_sha = "", ""
        if mode == "badsize":
            size_claim = rng.choice(["abc", "-4", "1.5", "99999999999999999999999"])
        if mode == "upper":
            claim_sha = claim_sha.upper()
        entry = {"rel": path_rel, "name": rel, "mode": mode, "cred": cred, "data": data, "claim_size": size_claim, "claim_sha": claim_sha}
        if mode == "nofile":
            case.files.pop(path_rel, None)
            entry["exists"] = False
            if cred:
                case.canaries += [sha("sha1", data), sha("sha256", data), sha("md5", data)]
        elif mode == "linkat":
            full = os.path.join(case.base, "inputs", "c", path_rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            os.symlink("/etc/hostname", full)
            case.files[path_rel] = {"data": b"", "cred": cred, "kind": "l"}
            entry["exists"] = True
            entry["kind"] = "l"
            if cred:
                case.canaries += [sha("sha1", data)]
        elif mode == "fifoat":
            full = os.path.join(case.base, "inputs", "c", path_rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            os.mkfifo(full)
            case.files[path_rel] = {"data": b"", "cred": cred, "kind": "p"}
            entry["exists"] = True
            entry["kind"] = "p"
        else:
            case.put(path_rel, data, cred)
            entry["exists"] = True
            entry["kind"] = "f"
        rows.append([f"2026-02-14 09:12:{len(rows) % 60:02d}.123", win(rel), dest, size_claim, claim_sha, "False", "", "", "", "0.1"])
        model.append(entry)
        if mode == "dup":
            rows.append(list(rows[-1]))
            model.append(dict(entry, dup=True))
        if cred and claim_sha:
            case.canaries.append(claim_sha.lower())
    # stray files
    for k in range(rng.choice([0, 0, 1, 2])):
        case.put(os.path.join(run, "C", "Stray", f"s{k}.txt"), rdata(rng, 20), False)
    # a case twin of a normal row (Linux only: the file system must tell them apart)
    if rng.random() < 0.15:
        for e in model:
            if e["mode"] == "normal" and e["exists"] and e["kind"] == "f":
                twin = os.path.join(os.path.dirname(e["rel"]), os.path.basename(e["rel"]).swapcase())
                if twin != e["rel"] and not os.path.exists(os.path.join(case.base, "inputs", "c", twin)):
                    case.put(twin, rdata(rng, 7), False)
                    e["twin"] = True
                break
    log = csv_text(rows, KAPE_HEADER)
    case.model_rows = getattr(case, "model_rows", [])
    ts = f"2026-02-14T0912{rng.randint(0, 59):02d}"
    logname = f"{ts}_CopyLog.csv"
    # damage the log text
    dmg = rng.choices(["none", "bom", "trunc", "garbage_line", "utf16", "header_only", "extra_col", "huge_field", "lf"], [60, 8, 6, 6, 4, 3, 5, 3, 5])[0]
    raw = log.encode()
    modelable = True
    if dmg == "bom":
        raw = b"\xef\xbb\xbf" + raw
    elif dmg == "trunc":
        raw = raw[: rng.randint(len(raw) // 2, len(raw))]
        modelable = False
    elif dmg == "garbage_line":
        lines = raw.split(b"\r\n")
        lines.insert(rng.randint(1, len(lines) - 1), b"\x00\xff\xfe garbage,\"unterminated")
        raw = b"\r\n".join(lines)
        modelable = False
    elif dmg == "utf16":
        raw = log.encode("utf-16")
        modelable = False
    elif dmg == "header_only":
        raw = (",".join(KAPE_HEADER) + "\r\n").encode()
        modelable = False
    elif dmg == "extra_col":
        raw = log.replace("\r\n", ",extra\r\n").encode()
        modelable = False
    elif dmg == "huge_field":
        raw = log.encode() + b"x," + b"A" * 1100000 + b"\r\n"
        modelable = False
    elif dmg == "lf":
        raw = log.replace("\r\n", "\n").encode()
    full = os.path.join(case.base, "inputs", "c", run, logname)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    open(full, "wb").write(raw)
    case.record_files = getattr(case, "record_files", set())
    case.record_files.add(os.path.join(run, logname))
    skip = rng.random() < 0.7
    if skip:
        sk = f"{ts}_SkipLog.csv"
        open(os.path.join(case.base, "inputs", "c", run, sk), "w").write("SourceFile,SourceFileSha1,Reason\r\nC:\\pagefile.sys,,locked by the system\r\nC:\\hiberfil.sys,,\"in use\"\r\n")
        case.record_files.add(os.path.join(run, sk))
    if rng.random() < 0.5:
        cl = f"{ts}_ConsoleLog.txt"
        open(os.path.join(case.base, "inputs", "c", run, cl), "w").write("[2026-02-14 09:12:00.1234567 | INF] start\n[2026-02-14 09:12:01.1 | WRN] Deferring x\n[2026-02-14 09:12:02.1 | ERR] boom\n")
        case.record_files.add(os.path.join(run, cl))
    case.collectors.append(("kape", run, logname, dmg, modelable and dmg in ("none", "bom", "lf"), model))
    case.model_rows += [(run, logname, i + 1, e, modelable and dmg in ("none", "bom", "lf")) for i, e in enumerate(model) if not e.get("dup") or True]


def gen_uac(case, rng, d):
    lines = []
    for i in range(rng.randint(1, 8)):
        lines.append(f"2026-02-14 09:12:{i:02d} +0000 {rng.choice(['INF', 'ERR', 'DBG', 'CMD'])} step {i}" + (" 2> x" if rng.random() < 0.1 else ""))
    if rng.random() < 0.3:
        lines.append("something unlabelled error happened")
    if rng.random() < 0.1:
        lines.append("A" * 1100000)
    os.makedirs(os.path.join(case.base, "inputs", "c", d), exist_ok=True)
    open(os.path.join(case.base, "inputs", "c", d, "uac.log"), "w").write("\n".join(lines) + "\n")
    case.record_files.add(os.path.join(d, "uac.log"))
    hl = []
    for name in rng.sample(PLAIN_NAMES + CRED_NAMES, rng.randint(1, 5)):
        cred = name in CRED_NAMES
        data = rdata(rng, rng.choice([5, 50, 300]), cred=cred)
        rel = os.path.join(d, "[root]", name)
        if rng.random() < 0.8:
            case.put(rel, data, cred)
        elif cred:
            case.canaries += [sha("md5", data), sha("sha1", data), sha("sha256", data)]
        alg = rng.choice(["md5", "sha1", "sha256"])
        dig = sha(alg, data) if rng.random() < 0.8 else "".join(rng.choice("0123456789abcdef") for _ in range(len(sha(alg, b""))))
        if cred:
            case.canaries.append(dig)
        hl.append((alg, f"{dig}  /{name}"))
    for alg in ("md5", "sha1", "sha256"):
        sel = [x for a, x in hl if a == alg]
        if sel:
            p = os.path.join(case.base, "inputs", "c", d, "hash_executables")
            os.makedirs(p, exist_ok=True)
            open(os.path.join(p, f"hash_executables.{alg}"), "w").write("\n".join(sel) + ("\n" if rng.random() < 0.9 else ""))
            case.record_files.add(os.path.join(d, "hash_executables", f"hash_executables.{alg}"))
    case.collectors.append(("uac", d, None, "none", False, []))


def gen_velo(case, rng, d):
    up_rows, res_rows = [], []
    names = rng.sample(PLAIN_NAMES + CRED_NAMES, rng.randint(1, 5))
    for name in names:
        cred = name in CRED_NAMES
        data = rdata(rng, rng.choice([5, 50, 300]), cred=cred)
        stored = "auto/C%3A/" + name
        if rng.random() < 0.9:
            case.put(os.path.join(d, "uploads", stored), data, cred)
        elif cred:
            case.canaries += [sha("sha1", data), sha("sha256", data), sha("md5", data)]
        up_rows.append(json.dumps({"vfs_path": stored, "file_size": len(data), "uploaded_size": len(data) if rng.random() < 0.9 else max(0, len(data) - 1)}))
        up = {"Path": "C:\\" + name.replace("/", "\\"), "Size": len(data), "StoredSize": len(data), "StoredName": stored, "Accessor": "auto", "Components": stored.split("/")}
        if rng.random() < 0.8:
            up["sha256"] = sha("sha256", data)
            up["md5"] = sha("md5", data)
            if rng.random() < 0.5:
                up["Sha1"] = sha("sha1", data)
            if rng.random() < 0.3:
                up["Hashes"] = {"SHA256": sha("sha256", data), "list": [sha("md5", data)]}
            if cred:
                case.canaries += [sha("sha1", data), sha("sha256", data), sha("md5", data)]
        if cred and rng.random() < 0.3:
            # the digest of a credential store nested in the collector's own record, 1 to 14 levels down, under a digest-named key
            deep = {rng.choice(["sha256", "Sha1", "md5", "digest"]): sha("sha256", data)}
            case.canaries.append(deep[next(iter(deep))])
            for level in range(rng.randint(1, 14)):
                deep = {"n%d" % level: deep}
            up["Wrap"] = deep
        if rng.random() < 0.15:
            up["Error"] = "Access is denied"
        res_rows.append(json.dumps({"_Source": "A", "Upload": up}))
    base = os.path.join(case.base, "inputs", "c", d)
    os.makedirs(os.path.join(base, "results"), exist_ok=True)
    if rng.random() < 0.95:
        open(os.path.join(base, "uploads.json"), "w").write("\n".join(up_rows) + "\n")
        case.record_files.add(os.path.join(d, "uploads.json"))
    open(os.path.join(base, "collection_context.json"), "w").write("{}")
    case.record_files.add(os.path.join(d, "collection_context.json"))
    if rng.random() < 0.85:
        txt = "\n".join(res_rows) + "\n"
        if rng.random() < 0.1:
            txt = "[" + ",".join(res_rows) + "]"
        elif rng.random() < 0.1:
            txt += "{not json\n"
        open(os.path.join(base, "results", "A.json"), "w").write(txt)
        case.record_files.add(os.path.join(d, "results", "A.json"))
    if rng.random() < 0.8:
        open(os.path.join(base, "log.json"), "w").write(json.dumps({"level": "INFO", "message": "ok"}) + "\n" + (json.dumps({"level": "ERROR", "message": "boom"}) + "\n" if rng.random() < 0.3 else ""))
        case.record_files.add(os.path.join(d, "log.json"))
    case.collectors.append(("velo", d, None, "none", False, []))


def gen_case(seed, base):
    rng = random.Random(seed)
    case = Case(rng, base)
    case.record_files = set()
    case.model_rows = []
    os.makedirs(os.path.join(base, "inputs", "c"), exist_ok=True)
    kinds = rng.choices(["kape", "uac", "velo", "mixed", "kape2"], [40, 15, 15, 15, 15])[0]
    if kinds in ("kape", "mixed", "kape2"):
        gen_kape(case, rng, rng.choice(["k1", "run/k1", ""]))
    if kinds == "kape2":
        gen_kape(case, rng, "k2")
    if kinds in ("uac", "mixed"):
        gen_uac(case, rng, "uac-host")
    if kinds in ("velo", "mixed"):
        gen_velo(case, rng, "v1")
    # a nested archive somewhere
    case.nested = False
    if rng.random() < 0.15:
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("K/2026_CopyLog.csv", csv_text([], KAPE_HEADER))
        loc = rng.choice(["inner.zip", "k1/data.zip", "uac-host/[root]/var/log/x.tar.gz"])
        p = os.path.join(base, "inputs", "c", loc)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "wb").write(inner.getvalue())
        case.files[loc] = {"data": inner.getvalue(), "cred": False, "kind": "f"}
        case.nested = loc
    # unlistable directory (not as root)
    if SELF_UID != 0 and rng.random() < 0.15:
        d = os.path.join(base, "inputs", "c", "Locked")
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "hidden.txt"), "w").write("h")
        os.chmod(d, 0)
        case.unreadable_dir = d
        case.census_incomplete = True
    # an unreadable file
    case.unreadable_files = []
    if SELF_UID != 0 and rng.random() < 0.15:
        for rel, info in list(case.files.items()):
            if info["kind"] == "f" and not info["cred"] and rel not in case.record_files:
                os.chmod(os.path.join(base, "inputs", "c", rel), 0)
                case.unreadable_files.append(rel)
                break
    # a name that is not UTF-8
    if rng.random() < 0.05:
        try:
            open(os.path.join(base.encode(), b"inputs", b"c", b"bad\xff\xfe.txt"), "wb").write(b"x")
        except OSError:
            pass
    return case


def unlock(case):
    if case.unreadable_dir:
        os.chmod(case.unreadable_dir, 0o755)
    for rel in case.unreadable_files:
        try:
            os.chmod(os.path.join(case.base, "inputs", "c", rel), 0o644)
        except OSError:
            pass


# ---------------------------------------------------------------------------------------------------------------------------------


def run_tool(pack, name, args, cwd, job=False, secret=False, timeout=120):
    env = dict(os.environ, AGENT_ID="a1")
    for k in ("JOB_ID", "OUT", "SECRET_OUTPUT"):
        env.pop(k, None)
    if job:
        out = os.path.join(cwd, "out")
        os.makedirs(out, exist_ok=True)
        env.update(JOB_ID="j000001", OUT=out)
        if secret:
            env["SECRET_OUTPUT"] = "1"
    t = time.time()
    try:
        p = subprocess.run([sys.executable, "-I", os.path.join(pack, "tools", name, "run.py")], input=json.dumps(args), capture_output=True, text=True, errors="replace", cwd=cwd, env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "", "TIMEOUT", None, time.time() - t
    try:
        out = json.loads(p.stdout)
    except Exception:
        out = None
    return p.returncode, p.stdout, p.stderr, out, time.time() - t


def read_outputs(cwd, skip_values=True):
    text = []
    for dp, dn, fn in os.walk(cwd):
        if os.path.relpath(dp, cwd).split(os.sep)[0] in ("inputs", "arch"):
            continue
        for f in fn:
            if skip_values and f.endswith("-values.jsonl"):
                continue
            try:
                text.append(open(os.path.join(dp, f), "rb").read().decode("utf-8", "replace"))
            except OSError:
                pass
    return "\n".join(text)


def tables(cwd, answer, key):
    info = (answer or {}).get("tables", {}).get(key) or {}
    p = info.get("all_results")
    if not p:
        return []
    full = os.path.join(cwd, p) if not p.startswith("store/jobs/") else os.path.join(cwd, "out", p.split("/out/")[1])
    try:
        return [json.loads(l) for l in open(full, encoding="utf-8", errors="replace") if l.strip()]
    except (OSError, ValueError):
        return []


class Report:
    def __init__(self):
        self.runs = {}
        self.findings = []
        self.notes = {}

    def count(self, tool):
        self.runs[tool] = self.runs.get(tool, 0) + 1

    def find(self, tool, seed, what, extra=None):
        self.findings.append({"tool": tool, "seed": seed, "what": what, **({"extra": extra} if extra else {})})


def common_oracle(rep, tool, seed, case, rc, stdout, stderr, answer, el, cwd, limit_s=60):
    if stderr == "TIMEOUT":
        rep.find(tool, seed, "timeout")
        return False
    if answer is None:
        rep.find(tool, seed, "stdout is not JSON", stdout[:200])
        return False
    if "Traceback" in stderr or "Traceback" in stdout:
        rep.find(tool, seed, "traceback")
    if stderr.strip():
        rep.find(tool, seed, "stderr is not empty", stderr[:200])
    if el > limit_s:
        rep.find(tool, seed, "slow", "%.1fs" % el)
    if rc not in (0, 2, 1):
        rep.find(tool, seed, "exit code %s" % rc)
    text = stdout + read_outputs(cwd)
    for c in set(case.canaries) - EMPTY:
        if c and (c in text or c.upper() in text):
            rep.find(tool, seed, "credential-store digest printed", c)
            break
    if answer.get("ok") is False and "error" in answer and rc == 0:
        rep.find(tool, seed, "ok false with exit 0")
    return True


GLOBS = ["*", "*/config/sam", "*.txt", "c:/windows/*", "*stray*", "*/etc/*", "*nothing*", "*/users/?/*", "*.pf", "*[root]*"]


def norm(p):
    return p.replace("\\", "/").casefold()


def gmatch(pat, text):
    rx = "^" + "".join(".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in norm(pat)) + "$"
    return re.search(rx, text, re.S) is not None


def census_files(case):
    root = os.path.join(case.base, "inputs", "c")
    out = []
    for dp, dn, fn in os.walk(root):
        for f in fn:
            full = os.path.join(dp, f)
            rel = os.path.relpath(full, root)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            out.append(rel)
    return out


def check_tools(pack, seed, case, rep, which, rng):
    cwd = case.base
    job = rng.random() < 0.4
    wv = job and rng.random() < 0.5
    results = {}
    common_args = {"root": "inputs/c"}
    verify_answer = None
    if "parse" in which:
        rep.count("parse")
        args = dict(common_args, limit=rng.choice([1, 5, 200]))
        if rng.random() < 0.3:
            args["collectors"] = rng.sample(["kape", "uac", "velociraptor"], rng.randint(1, 3))
        if wv:
            args["write_values"] = True
        rc, so, se, ans, el = run_tool(pack, "collection_manifest_parse", args, cwd, job, wv)
        if common_oracle(rep, "parse", seed, case, rc, so, se, ans, el, cwd):
            if ans.get("ok") is not False and ans.get("status") not in ("complete", "partial"):
                rep.find("parse", seed, "status", ans.get("status"))
            if case.census_incomplete and ans.get("ok") is not False and ans.get("status") == "complete":
                rep.find("parse", seed, "complete over an unlistable directory")
        shutil.rmtree(os.path.join(cwd, "work"), ignore_errors=True)
        shutil.rmtree(os.path.join(cwd, "out"), ignore_errors=True)
    if "verify" in which or "coverage" in which or "path_map" in which:
        if "verify" in which:
            rep.count("verify")
        args = dict(common_args, limit=rng.choice([1, 5, 200]), hash=rng.random() < 0.85)
        if wv:
            args["write_values"] = True
        rc, so, se, ans, el = run_tool(pack, "collection_manifest_verify", args, cwd, job, wv)
        verify_answer = ans
        ok = common_oracle(rep, "verify", seed, case, rc, so, se, ans, el, cwd) if "verify" in which else (ans is not None)
        if ok and ans.get("ok") is not False:
            checks = tables(cwd, ans, "checks")
            results["verify_checks"] = checks
            results["verify_unexpected"] = {u["delivered"] for u in tables(cwd, ans, "unexpected")}
            if "verify" in which:
                verify_oracle(rep, seed, case, ans, checks, args)
            results["verify"] = ans
            results["verify_args"] = args
        # keep the verification table for coverage before deleting work/
        if ans and ans.get("ok") is not False:
            vt = (ans.get("tables", {}).get("checks") or {}).get("all_results")
            if vt:
                dst = os.path.join(cwd, "vtable.jsonl")
                src = os.path.join(cwd, vt) if not vt.startswith("store/jobs/") else os.path.join(cwd, "out", vt.split("/out/")[1])
                try:
                    shutil.copy(src, dst)
                    results["vtable"] = "vtable.jsonl"
                except OSError:
                    pass
    if "path_map" in which:
        rep.count("path_map")
        existing = census_files(case)
        args = dict(common_args, limit=rng.choice([1, 5, 200]))
        if rng.random() < 0.3 and existing:
            args["paths"] = rng.sample(existing, min(len(existing), 3)) + ["nope/x.txt", "../../etc/passwd"]
        if wv:
            args["write_values"] = True
        rc, so, se, ans, el = run_tool(pack, "collection_path_map", args, cwd, job, wv)
        if common_oracle(rep, "path_map", seed, case, rc, so, se, ans, el, cwd) and ans.get("ok") is not False:
            rows = tables(cwd, ans, "mappings")
            results["pm_rows"] = rows
            by = {r["delivered"]: r["status"] for r in rows}
            results["pm_status"] = by
            if "paths" not in args:
                pm_oracle(rep, seed, case, ans, rows, results)
            else:
                names = {r["delivered"] for r in rows}
                for p in args["paths"]:
                    if p.startswith(".."):
                        if p in names:
                            rep.find("path_map", seed, "a path outside the delivery was mapped", p)
    if "coverage" in which:
        rep.count("coverage")
        pats = GLOBS
        qs = []
        for i in range(rng.randint(1, 4)):
            q = {"id": "q%d" % i}
            if rng.random() < 0.5:
                q["delivered_paths"] = rng.sample(pats, rng.randint(1, 2))
            if rng.random() < 0.5 or "delivered_paths" not in q:
                q["source_paths"] = rng.sample(pats, rng.randint(1, 2))
            qs.append(q)
        qs.append({"id": "all", "delivered_paths": ["*"]})
        args = dict(common_args, questions=qs, limit=rng.choice([1, 5, 200]), requested=rng.sample(pats + ["c:/windows/a.txt", "c:/gone/*"], rng.randint(0, 3)))
        if rng.random() < 0.3:
            args["examined"] = rng.sample(pats, 1)
        if results.get("vtable") and rng.random() < 0.5:
            args["verification"] = results["vtable"]
        if wv:
            args["write_values"] = True
        rc, so, se, ans, el = run_tool(pack, "collection_coverage", args, cwd, job, wv)
        if common_oracle(rep, "coverage", seed, case, rc, so, se, ans, el, cwd) and ans.get("ok") is not False:
            coverage_oracle(rep, seed, case, ans, args, results)
    shutil.rmtree(os.path.join(cwd, "work"), ignore_errors=True)
    shutil.rmtree(os.path.join(cwd, "out"), ignore_errors=True)
    return results


def verify_oracle(rep, seed, case, ans, checks, args):
    if ans.get("status") not in ("complete", "partial"):
        rep.find("verify", seed, "status", ans.get("status"))
    inc = not ans["census"]["complete"]
    if case.census_incomplete and not inc:
        rep.find("verify", seed, "the census is complete over an unlistable directory")
    if inc and ans["by_status"].get("missing", 0):
        rep.find("verify", seed, "missing said with an incomplete census")
    if inc and ans.get("status") == "complete":
        rep.find("verify", seed, "complete with an incomplete census")
    # the plain KAPE rows against an independent model
    byloc = {}
    for c in checks:
        loc = c.get("locator") or {}
        byloc[(loc.get("log"), loc.get("row"))] = c
    for run, logname, idx, e, modelable in case.model_rows:
        if not modelable or e.get("dup"):
            continue
        row = byloc.get((os.path.join(run, logname).replace(os.sep, "/").lstrip("/"), idx))
        if row is None:
            rep.find("verify", seed, "a copy-log row is not in the checks table", [run, logname, idx, e["mode"]])
            continue
        exp = expected_status(case, e, args, inc)
        if exp and row["status"] != exp:
            rep.find("verify", seed, "status differs from the model", {"mode": e["mode"], "expected": exp, "got": row["status"], "path": row["path"], "size": row["size"], "hash": {k: v for k, v in row["hash"].items() if k != "measured"}})


def expected_status(case, e, args, census_incomplete):
    if e.get("twin"):
        return "ambiguous"
    mode = e["mode"]
    if mode == "weak":
        return "ambiguous"
    if not e["exists"]:
        return "unverifiable" if census_incomplete else "missing"
    if e.get("kind") in ("l", "p"):
        return "unverifiable"
    unreadable = e["rel"] in case.unreadable_files
    size_ok = bad_size = False
    cs = e["claim_size"]
    if cs not in ("", None):
        if re.fullmatch(r"[0-9]{1,20}", cs):
            if int(cs) == len(e["data"]):
                size_ok = True
            else:
                bad_size = True
    hash_claim = bool(e["claim_sha"]) and re.fullmatch(r"[0-9A-Fa-f]{40}", e["claim_sha"]) is not None
    if hash_claim:
        if not args.get("hash", True):
            return "mismatch" if bad_size else "unverifiable"
        if unreadable and SELF_UID != 0:
            return "read_failed"
        if e["claim_sha"].lower() != sha("sha1", e["data"]):
            return "mismatch"
        if bad_size:
            return "mismatch"
        return "matched"
    if bad_size:
        return "mismatch"
    if size_ok:
        return "matched"
    return "unverifiable"


def pm_oracle(rep, seed, case, ans, rows, results):
    inc = not ans["census"]["complete"]
    if ans.get("status") == "complete" and inc:
        rep.find("path_map", seed, "complete with an incomplete census")
    st = results.get("verify_unexpected")
    if st is not None:
        for rel in st:
            s = results["pm_status"].get(rel)
            if s not in ("hypothesis_only", None):
                rep.find("path_map", seed, "verify says unexpected, path_map says %s" % s, rel)
    for rel, s in results["pm_status"].items():
        if s == "candidate_of_ambiguous_record" and st is not None and rel in st:
            rep.find("path_map", seed, "candidate of an ambiguous record is unexpected in verify", rel)
    # every status is a known one
    for c in results.get("verify_checks") or []:
        if c["path"]["result"] == "ambiguous":
            for cand in (c["path"].get("candidates") or []):
                if st is not None and cand in st:
                    rep.find("verify", seed, "a candidate of an ambiguous record is unexpected", cand)
                if results["pm_status"].get(cand) == "hypothesis_only":
                    rep.find("path_map", seed, "a candidate of an ambiguous record is hypothesis_only", cand)
    for rel, s in results["pm_status"].items():
        if s not in ("observed", "ambiguous", "hypothesis_only", "collector_record", "candidate_of_ambiguous_record"):
            rep.find("path_map", seed, "unknown status", s)


def coverage_oracle(rep, seed, case, ans, args, results):
    inc = not ans["census"]["complete"]
    if case.census_incomplete and not inc:
        rep.find("coverage", seed, "the census is complete over an unlistable directory")
    files = [f for f in census_files(case) if f not in case.record_files]
    record_files = {r.replace(os.sep, "/") for r in case.record_files}
    files = [f for f in census_files(case) if f.replace(os.sep, "/") not in record_files]
    qs = {q["id"]: q for q in args["questions"]}
    for q in ans["questions"]:
        spec = qs[q["id"]]
        stmt = q["statement"]
        if inc:
            if "no_file_and_no_record" in q["state"]:
                rep.find("coverage", seed, "no_file_and_no_record over an incomplete census", q["id"])
            if "The delivery holds nothing under these patterns" in stmt:
                rep.find("coverage", seed, "'holds nothing' over an incomplete census", q["id"])
            if "census_incomplete" not in q["state"]:
                rep.find("coverage", seed, "state lacks census_incomplete", q["id"])
            if q["copied_but_not_in_the_delivery"]:
                rep.find("coverage", seed, "copied_but_not_in_the_delivery over an incomplete census", q["id"])
        else:
            if q["delivered_files"] == 0 and q["records_copied_or_uploaded"] == 0 and q["records_failed_or_skipped"] == 0 and q["hash_list_lines"] == 0:
                if "no_file_and_no_record" not in q["state"] and "no_file_and_no_record_read" not in q["state"]:
                    rep.find("coverage", seed, "a complete census with nothing found lacks no_file_and_no_record", q["id"])
        # delivered-only questions: the count of files is the model's
        if spec.get("delivered_paths") and not spec.get("source_paths"):
            exp = sum(1 for f in files if any(gmatch(p, norm(f)) for p in spec["delivered_paths"]))
            if q["delivered_files"] != exp and not ans["census"]["capped"]:
                rep.find("coverage", seed, "delivered_files differs from the model", {"q": q["id"], "exp": exp, "got": q["delivered_files"], "pats": spec["delivered_paths"]})
    for r in ans["requested"]:
        if inc and r["state"] in ("recorded_not_delivered", "neither_delivered_nor_recorded"):
            rep.find("coverage", seed, "requested %s over an incomplete census" % r["state"], r["pattern"])
        if r["state"] not in ("delivered", "recorded_not_delivered", "recorded_delivery_not_decided", "recorded_as_skipped_or_failed", "unknown_census_incomplete", "unknown_records_unread", "neither_delivered_nor_recorded"):
            rep.find("coverage", seed, "unknown requested state", r["state"])
    # coverage and verify agree on the files in scope that no record names
    v = results.get("verify")
    if v is not None and not inc and results.get("verify_args", {}).get("limit") is not None:
        allq = next((q for q in ans["questions"] if q["id"] == "all"), None)
        if allq is not None and ans["census"]["complete"] and v["census"]["complete"]:
            vu = v["by_status"].get("unexpected", 0)
            if allq["delivered_without_a_record"] != vu:
                rep.find("coverage", seed, "delivered_without_a_record differs from verify's unexpected", [allq["delivered_without_a_record"], vu])


# ---- the recipe ----------------------------------------------------------------------------------------------------------------------


def pack_tree(case, kind, rng, dest):
    root = os.path.join(case.base, "inputs", "c")
    members = []
    for dp, dn, fn in os.walk(root):
        for d in dn:
            pass
        for f in sorted(fn):
            full = os.path.join(dp, f)
            rel = os.path.relpath(full, root)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            if rel in case.unreadable_files:
                continue
            try:
                members.append((rel.replace(os.sep, "/"), open(full, "rb").read()))
            except OSError:
                pass
    members.sort()
    rng.shuffle(members)
    if kind == "zip":
        kept = []
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
            for n, d in members:
                try:
                    z.writestr(n, d)
                except UnicodeEncodeError:
                    case.zip_dropped = True        # a zip cannot hold a name that is not UTF-8 (a Linux name of raw bytes)
                    continue
                kept.append((n, d))
        return kept
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as t:
        for n, d in members:
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            t.addfile(ti, io.BytesIO(d))
        if rng.random() < 0.3:
            ti = tarfile.TarInfo("lnk")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "/etc/passwd"
            t.addfile(ti)
    data = raw.getvalue()
    return members, data


def recipe_case(pack, seed, case, rep, rng, kept_cap=None):
    rep.count("recipe")
    cwd = case.base
    arch = os.path.join(cwd, "arch")
    os.makedirs(arch, exist_ok=True)
    kind = rng.choice(["zip", "tar", "tar", "tgz", "tbz2", "txz"])
    cut = None
    damaged = False             # bytes of the archive were changed: a name in a record may no longer be the credential store's, so the name hint cannot hold its digest
    dest = os.path.join(arch, "a." + {"zip": "zip", "tar": "tar", "tgz": "tgz", "tbz2": "tbz2", "txz": "txz"}[kind])
    if kind == "zip":
        members = pack_tree(case, "zip", rng, dest)
        if not members:
            return
        roll = rng.random()
        if roll < 0.08:
            # another zip in front of this one, or after it: a reader follows the last central directory only
            other = io.BytesIO()
            with zipfile.ZipFile(other, "w") as z2:
                z2.writestr("other/2027_CopyLog.csv", "SourceFile\r\n")
            mine = open(dest, "rb").read()
            open(dest, "wb").write(other.getvalue() + mine if rng.random() < 0.5 else mine + other.getvalue())
            cut = "garbage"
        elif roll < 0.14:
            open(dest, "ab").write(b"X" * rng.randint(1, 40))
            cut = "garbage"
    else:
        res = pack_tree(case, "tar", rng, dest)
        members, data = res
        if not members:
            return
        endpad = rng.choice([0, 1, 2, 20])
        # the member area ends where the next header would start (not at the last zero byte: a member's data can end in zeros)
        tfm = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
        for _m in tfm:
            pass
        body = data[: tfm.offset]
        tfm.close()
        if kind == "tar":
            roll = rng.random()
            if roll < 0.35:
                cut = rng.choice(["boundary", "mid_header", "mid_data", "none_marker_missing"])
                # offsets of member starts
                starts, off = [], 0
                # recompute offsets by walking headers
                bio = io.BytesIO(body)
                tf = tarfile.open(fileobj=bio, mode="r:")
                for m in tf:
                    starts.append(m.offset)
                tf.close()
                starts.append(len(body))
                k = rng.randint(1, max(1, len(starts) - 1)) if len(starts) > 1 else 1
                if cut == "boundary":
                    out = body[: starts[min(k, len(starts) - 1)]]
                elif cut == "mid_header":
                    out = body[: starts[min(k - 1, len(starts) - 1)] + rng.randint(1, 511)]
                elif cut == "mid_data":
                    s = starts[min(k - 1, len(starts) - 1)]
                    e2 = starts[min(k, len(starts) - 1)]
                    out = body[: s + 512 + max(0, (e2 - s - 512) // 2)] if e2 - s > 1024 else body[: s + 600]
                else:
                    out = body
                data_out = out
                if cut == "none_marker_missing":
                    cut = "boundary"
            else:
                data_out = body + b"\0" * (512 * endpad if endpad else 1024)
                if rng.random() < 0.08:
                    # the block where the end marker should start is damaged (not zero, not a header), then zeros
                    data_out = body + bytes(rng.randint(1, 255) for _ in range(512)) + b"\0" * 1024
                    cut = "garbage"
                elif rng.random() < 0.1:
                    data_out += b"trailing garbage not zero"
                    cut = "garbage"
                elif rng.random() < 0.08:
                    second = io.BytesIO()
                    with tarfile.open(fileobj=second, mode="w") as t2:
                        ti = tarfile.TarInfo("second/2026_CopyLog.csv")
                        ti.size = 1
                        t2.addfile(ti, io.BytesIO(b"x"))
                    data_out += second.getvalue()
                    cut = "garbage"
            open(dest, "wb").write(data_out)
        else:
            full = body + b"\0" * 1024
            comp = {"tgz": gzip.compress, "tbz2": bz2.compress, "txz": lzma.compress}[kind]
            blob = comp(full)
            roll = rng.random()
            if roll < 0.3:
                blob = blob[: rng.randint(len(blob) // 3, len(blob) - 1)]
                cut = "compressed"
            elif roll < 0.4:
                blob = blob + comp(b"\0" * 1024 if rng.random() < 0.5 else full)         # a second stream (gzip member, bzip2 stream, xz stream)
                cut = "garbage"
            elif roll < 0.47:
                blob = blob + bytes(rng.randint(1, 255) for _ in range(rng.randint(1, 30)))
                cut = "garbage"
            elif roll < 0.62:
                # one flipped bit anywhere: if a module reading the stream whole does not return the same tar, the recipe must not be complete
                at = rng.randrange(len(blob))
                flipped = bytearray(blob)
                flipped[at] ^= 1 << rng.randrange(8)
                blob = bytes(flipped)
                try:
                    same = {"tgz": gzip.decompress, "tbz2": bz2.decompress, "txz": lzma.decompress}[kind](blob) == full
                except Exception:
                    same = False
                if not same:
                    cut = "compressed"
                    damaged = True
            open(dest, "wb").write(blob)
    env = dict(os.environ)
    if kept_cap:
        env["COLLECTION_INTAKE_KEPT_TOTAL_BYTES"] = str(kept_cap)
    t = time.time()
    outdir = os.path.join(cwd, "ro")
    det = subprocess.run([sys.executable, "-I", os.path.join(pack, "recipes", "collection-intake", "run.py"), "detect", "--target", json.dumps({"paths": [dest]})], capture_output=True, text=True, errors="replace", env=env, timeout=300)
    run = subprocess.run([sys.executable, "-I", os.path.join(pack, "recipes", "collection-intake", "run.py"), "run", "--target", json.dumps({"paths": [dest]}), "--out", outdir], capture_output=True, text=True, errors="replace", env=env, timeout=600, cwd=cwd)
    el = time.time() - t
    if "Traceback" in det.stderr + det.stdout + run.stderr + run.stdout:
        rep.find("recipe", seed, "traceback", (det.stderr + run.stderr)[-300:])
    try:
        json.loads(det.stdout)
    except Exception:
        rep.find("recipe", seed, "detect is not JSON", det.stdout[:200])
    if det.returncode not in (0, 1, 2):
        rep.find("recipe", seed, "detect exit %s" % det.returncode)
    try:
        json.loads(run.stdout)
    except Exception:
        rep.find("recipe", seed, "run stdout is not JSON", run.stdout[:200])
    if el > 120:
        rep.find("recipe", seed, "slow", "%.1fs" % el)
    out_text = ""
    if os.path.isdir(outdir):
        left = [f for f in os.listdir(outdir) if f.startswith(".")]
        if left:
            rep.find("recipe", seed, "temporary files left", left)
        for f in os.listdir(outdir):
            p = os.path.join(outdir, f)
            if os.path.isfile(p):
                out_text += open(p, "rb").read().decode("utf-8", "replace")
    for c in set(case.canaries) - EMPTY:
        if not damaged and c and (c in out_text or c.upper() in out_text or c in run.stdout):
            rep.find("recipe", seed, "credential-store digest printed", c)
            break
    try:
        cov = json.load(open(os.path.join(outdir, "coverage.json")))
    except Exception:
        rep.find("recipe", seed, "no coverage.json")
        return
    if cov.get("status") not in ("complete", "partial", "failed"):
        rep.find("recipe", seed, "status", cov.get("status"))
    if cut in ("boundary", "mid_header", "mid_data", "compressed", "garbage") and cov.get("status") == "complete":
        rep.find("recipe", seed, "complete for a tar that is cut or has data after its end", cut)
    if cut in ("boundary", "mid_header") and os.path.isfile(os.path.join(outdir, "verification.jsonl")):
        for l in open(os.path.join(outdir, "verification.jsonl")):
            if l.strip() and json.loads(l)["status"] == "missing":
                rep.find("recipe", seed, "a claim is missing in a cut tar", cut)
                break
    if case.nested and cov.get("status") == "complete" and not any(case.nested.startswith(x) for x in ("uac-host/[root]",)):
        # a nested archive outside collected data (unless a record names it) must not leave the run complete
        named = False
        for l in open(os.path.join(outdir, "verification.jsonl")) if os.path.isfile(os.path.join(outdir, "verification.jsonl")) else []:
            if l.strip() and (json.loads(l).get("member") or "") == case.nested:
                named = True
        if not named and cov.get("nested_archives_total", 0):
            rep.find("recipe", seed, "complete with an unopened nested archive that may hold records", case.nested)
    if kept_cap and cov.get("records_kept_bytes", 0) > kept_cap:
        rep.find("recipe", seed, "kept more than the cap", [cov.get("records_kept_bytes"), kept_cap])
    # agree with the verify tool on the same tree when the archive is whole
    if (cut is None and kind in ("zip", "tar", "tgz", "tbz2", "txz") and not case.census_incomplete and not case.unreadable_files
            and not cov.get("records_not_kept_total_cap") and not cov.get("records_over_member_cap") and not getattr(case, "zip_dropped", False)):
        names_in_zip = {n for n, _d in members}
        rt = recipe_vs_tool(pack, case, outdir, rng, rep, seed)


def recipe_vs_tool(pack, case, outdir, rng, rep, seed):
    # the tool runs on the tree; links and FIFOs are not in the archive (zip/tar of regular files only), so a row whose file is a link/FIFO differs by design: skip those cases
    for _run, _log, _i, e, _m in case.model_rows:
        if e.get("kind") in ("l", "p"):
            return
    if any(info["kind"] != "f" for info in case.files.values()):
        return
    rc, so, se, ans, el = run_tool(pack, "collection_manifest_verify", {"root": "inputs/c", "limit": 100000}, case.base, False)
    if ans is None or ans.get("ok") is False:
        return
    tool_rows = tables(case.base, ans, "checks")
    try:
        rec_rows = [json.loads(l) for l in open(os.path.join(outdir, "verification.jsonl")) if l.strip()]
    except OSError:
        return
    strip = lambda r: (r["kind"], r["status"], r["path"]["result"], r["size"]["result"], r["hash"]["result"])
    a, b = sorted(map(strip, tool_rows)), sorted(map(strip, rec_rows))
    # a nested archive or a name the zip cannot hold may differ; report any difference once
    if a != b:
        rep.find("recipe", seed, "the recipe and the verify tool disagree on the same tree", {"tool": a[:6], "recipe": b[:6], "n": [len(a), len(b)]})
    shutil.rmtree(os.path.join(case.base, "work"), ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", required=True)
    ap.add_argument("--cases", type=int, default=1000)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--work", required=True)
    ap.add_argument("--tools", default="parse,verify,path_map,coverage,recipe")
    ap.add_argument("--out")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    a.pack = os.path.abspath(a.pack)
    a.work = os.path.abspath(a.work)
    which = set(a.tools.split(","))
    rep = Report()
    t0 = time.time()
    for i in range(a.start, a.start + a.cases):
        seed = a.seed * 1000003 + i
        base = os.path.join(a.work, "c%05d" % i)
        shutil.rmtree(base, ignore_errors=True)
        os.makedirs(base)
        rng = random.Random(seed ^ 0x5eed)
        try:
            case = gen_case(seed, base)
        except Exception as exc:
            rep.find("generator", seed, "generator failed", repr(exc))
            continue
        try:
            if which & {"parse", "verify", "path_map", "coverage"}:
                check_tools(a.pack, seed, case, rep, which, rng)
            if "recipe" in which:
                recipe_case(a.pack, seed, case, rep, rng, kept_cap=rng.choice([None, None, 3000, 100000]))
        except Exception as exc:
            import traceback
            rep.find("harness", seed, "harness error", traceback.format_exc()[-400:])
        finally:
            unlock(case)
            if not a.keep:
                shutil.rmtree(base, ignore_errors=True)
        if (i + 1) % 100 == 0:
            print("... %d cases, %d findings, %.0fs" % (i + 1 - a.start, len(rep.findings), time.time() - t0), flush=True)
    summary = {"cases": a.cases, "runs": rep.runs, "findings_total": len(rep.findings), "seconds": round(time.time() - t0, 1)}
    by = {}
    for f in rep.findings:
        k = (f["tool"], f["what"])
        by.setdefault(k, []).append(f["seed"])
    summary["findings_by_kind"] = {"%s: %s" % k: {"count": len(v), "first_seeds": v[:5]} for k, v in sorted(by.items())}
    print(json.dumps(summary, indent=1))
    if a.out:
        json.dump({"summary": summary, "findings": rep.findings}, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
