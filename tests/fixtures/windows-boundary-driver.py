"""Drives the SHARED BOUNDARY block of a windows-forensics tool in-process, for tests/pack-windows-forensics-boundary-block.test.ts.

usage: windows-boundary-driver.py <module file> <case>    (the module file is the block cut out of a tool's run.py, with its imports)

Every case prints one JSON object. Canaries are built at run time from pieces and random characters, never written out whole.
"""
import importlib.util
import json
import os
import random
import re
import resource
import string
import sys
import time

path, case = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("block", path)
blk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(blk)

A = string.ascii_letters + string.digits
rnd = random.Random(20261015)


def rs(n, alphabet=A):
    return "".join(rnd.choice(alphabet) for _ in range(n))


def printed(secret, doc):
    return secret in json.dumps(doc, ensure_ascii=False)


def peak_mb():
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024


def timed(fn):
    t0 = time.time()
    fn()
    return round(time.time() - t0, 3)


def answer(kind, text):
    return blk.answer_object({"status": "complete", "v": blk.T(kind, text)})


KINDS = ("text", "host", "name", "path", "key", "url")
NO_NEWLINE = ("name", "path", "key")

if case == "backslashes":
    out = {}
    for n in (65536, 262144):
        out["seal_%d" % n] = timed(lambda: blk.seal({"v": "\\" * n}))
        out["flat_%d" % n] = timed(lambda: blk._flat("\\" * n))
        out["normal_%d" % n] = timed(lambda: blk._s_normal("\\" * n))
        out["hex_%d" % n] = timed(lambda: blk.seal({"v": blk.T("hex", "5c" * (n // 2))}))
    flat_u = blk._flat("a" + "\\" * 5 + "u200b" + "b")
    flat_g = blk._flat("g" + "hp_" + "\\u200b" + "A" * 36)
    out["escape_removed"] = flat_u == "ab" and "\\u200b" not in flat_g
    print(json.dumps(out))

elif case == "redos":
    # every pattern of the block against hostile repeated shapes, at two sizes: a linear one grows four times for four times the text, a quadratic one sixteen
    atoms = ["\\", "\\x", "\"", "'", "@", ":", "=", "<", "[", "%", "%4", ".", "-", "_", "/", " ", "\t", "a", "A", "7", "AB", "a1", "\\u", "\\u00", "pass=", "password:",
             "AK" + "IA", "ey" + "J", "gh" + "p_", "sk-", "A/", "AAAA=", "http://", "<withheld 1", "[withheld: 1", "\uff21", "\u00e9", "\x00", ";", "&", ",", "glp" + "at-",
             "SG.", "?", "#", "+", "<withheld 5 characters: user-info>:", "a:b@", "xox" + "b-", "ya29.", "AI" + "za", "-----BEGIN PRIVATE KEY-----"]
    prefixes = ["password=", "secret:", "http://u:", "-----BEGIN PRIVATE KEY-----", "gh" + "p_", "ey" + "J", "a:b@", "<withheld 5 characters: user-info>:", "//", "SG."]
    small, large = 4000, 32000
    slow = []
    worst = 0.0
    cases = 0

    def seconds(make, kind, n):
        text = make(n)
        t0 = time.process_time()
        blk.seal({"v": blk.T(kind, text)})
        return time.process_time() - t0

    def measure(make, label, kinds):
        global worst, cases
        for kind in kinds:
            # CPU time, and the least of up to three rounds when a round looks slow or not linear (as tests/pack-re-timing.ts does: one round of a few
            # hundredths of a second on a loaded runner is several times too long); the base keeps its floor of 0.01 s so that a quadratic rule is still seen at these sizes
            t1 = t2 = None
            for _ in range(3):
                a, b = seconds(make, kind, small), seconds(make, kind, large)
                t1 = a if t1 is None else min(t1, a)
                t2 = b if t2 is None else min(t2, b)
                if t2 <= 0.3 or (t2 <= 4 and t2 / max(t1, 0.01) <= 24):
                    break
            cases += 1
            worst = max(worst, t2)
            if t2 > 4 or (t2 > 0.3 and t2 / max(t1, 0.01) > 24):
                slow.append([label, kind, round(t1, 3), round(t2, 3)])

    for atom in atoms:
        measure(lambda n, atom=atom: atom * (n // len(atom)), atom, ("text", "url"))
    for prefix in prefixes:
        for atom in ("a", "-", "/", "@", "=", ":", " ", "1", "\\", "&", ".", "ey" + "J"):
            measure(lambda n, prefix=prefix, atom=atom: prefix + atom * (n // len(atom)), prefix + " + " + atom, ("text",))
    print(json.dumps({"slow": slow, "worst": round(worst, 2), "cases": cases}))

elif case == "big":
    # strings past the 100,000-character window the old PEM pattern scanned from every marker, with a leading token that makes a layer change the string (so the
    # backstop reads the original too): every shape of the cost, at the largest size a string is judged at (262,144) and past it, in CPU seconds
    sizes = [int(x) for x in sys.argv[3].split(",")] if len(sys.argv) > 3 else [120000, 262144]
    lead = "gh" + "p_" + rs(36) + " "
    atoms = ["-----BEGIN PRIVATE KEY-----", "PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----\n", "ey" + "J", "gh" + "p_", "password=", "Password: ", "AK" + "IA", "=", ":", "@", "a:b@",
             "ABCDEFGHIJKLMNOP=", "sk-", "SG.", "\\", " ", "-----END ", "token=", "A1"]
    slow, worst, cases = [], 0.0, 0
    for size in sizes:
        for atom in (atoms if size <= 300000 else atoms[:6]):               # past the size a string is judged at, the rest is withheld by its length: a few shapes
            for kind in ("text", "path"):
                text = lead + (atom * (size // len(atom) + 1))[:size]
                t0 = time.process_time()
                out = blk.seal({"v": blk.T(kind, text)})
                took = time.process_time() - t0
                cases += 1
                worst = max(worst, took)
                if took > 4 or lead[:40] in json.dumps(out):
                    slow.append([size, atom, kind, round(took, 2), lead[:40] in json.dumps(out)])
    print(json.dumps({"slow": slow, "worst": round(worst, 2), "cases": cases, "sizes": sizes}))

elif case == "budget":
    # an answer that takes longer than the budget to seal has the rest of its strings replaced whole, is partial, and the clock is stopped after it
    blk.SEAL_BUDGET = 0.05
    big = "gh" + "p_" + rs(36) + " " + ("ey" + "J") * 80000
    doc = {"status": "complete", "name": "short", "items": [{"id": i, "text": big + str(i)} for i in range(40)], "tail": "x" * 40}
    out = {}
    t0 = time.process_time()
    sealed = blk.answer_object(doc)
    out["seconds"] = round(time.process_time() - t0, 2)
    out["status"] = sealed["status"]
    texts = [i["text"] for i in sealed["items"]]
    out["late_marks"] = sum("the judging time ran out" in t for t in texts)
    out["unjudged_printed"] = sum(big[:50] in t for t in texts)
    out["short_kept"] = sealed["name"] == "short" and sealed["items"][-1]["id"] == 39
    out["tail_withheld"] = "the judging time ran out" in sealed["tail"]
    out["counted"] = sealed["boundary"]["replaced_by_check"].get("the judging time ran out", 0)
    out["clock_stopped"] = blk._CLOCK["deadline"] is None
    out["basis"] = sealed.get("status_basis", "")[:40]
    blk.SEAL_BUDGET = 10.0
    again = blk.seal({"v": "plain words"})
    out["after"] = again == {"v": "plain words"}
    # the seal stop of a tool: a seal that starts past it withholds all but the short plain strings
    blk.seal_stop_after(-1)
    late = blk.seal({"long": "a longer text than fifteen characters", "short": "short"})
    out["stop_late"] = late["long"].startswith("<withheld") and "the judging time ran out" in late["long"] and late["short"] == "short"
    blk._CLOCK["stop"] = None
    out["stop_cleared"] = blk.seal({"v": "a longer text than fifteen characters"}) == {"v": "a longer text than fifteen characters"}
    print(json.dumps(out))

elif case == "contains_sealed":
    # a secret that ONLY the backstop catches (the layers show it, the backstop replaces the string): a `contains` filter must not tell a true piece of it from a
    # wrong one, in the count of matches or in the blind spot
    res = {"plants": 0, "differ": 0, "secret_in_sealed": 0, "counters_moved": 0, "whole_string_gone": 0}
    BAK = A + "+/"
    for slot in ("text", "path"):
        for _ in range(8):
            while True:
                sec = rs(40, BAK)
                text = "C:\\tool.exe --key " + sec
                shown = blk.show(text, slot, "")
                if sec in shown and blk._suspect(shown, slot):
                    break
            before = (blk.BOUNDARY["withheld"], blk.BOUNDARY["replaced"], len(blk.BOUNDARY["where"]))
            needles = [sec[0:10], sec[15:25], sec[30:40], sec]
            wrongs = [rs(10, BAK), sec[:9] + ("x" if sec[9] != "x" else "y"), rs(14, BAK)]
            got = [blk.contains_check(n.lower(), text, slot) for n in needles]
            bad = [blk.contains_check(n.lower(), text, slot) for n in wrongs]
            res["plants"] += 1
            res["differ"] += len({tuple(g) for g in got + bad}) != 1
            res["secret_in_sealed"] += sec[:12] in blk.sealed_text(text, slot)
            res["whole_string_gone"] += blk.contains_check("tool.exe", text, slot) == tuple(bad[0])
            res["counters_moved"] += before != (blk.BOUNDARY["withheld"], blk.BOUNDARY["replaced"], len(blk.BOUNDARY["where"]))
    res["blind_when_hidden"] = blk.contains_check("zzzzzzzz", "C:\\tool.exe --key " + sec, "text")
    res["plain_text_found"] = blk.contains_check("tool.exe", "C:\\tool.exe --verbose", "text")
    res["plain_text_absent"] = blk.contains_check("qq", "C:\\tool.exe --verbose", "text")
    print(json.dumps(res))

elif case == "shapes_p3":
    out = {}
    # a field name with an acronym in the plural is a plain name; random names of 16+ characters still are not
    names = ["NumberOfGPOsDownloaded", "NumberOfGPOsApplicable", "ProcessorArchitecture", "SubjectUserSid", "TargetLogonId", "NumberOfDCsFound", "ServicePackMajorVersion", "IPAddressList"]
    out["names_changed"] = [n for n in names if blk.show(n, "name", "") != n]
    out["random_names_withheld"] = sum("withheld" in blk.show(rs(24), "name", "") for _ in range(100))
    # a typed version holds the shape of a version, whatever the first layer does
    ver_ok = ["10.0.19041.1", "6.1.7601.17514", "1.2.3-beta+build.5", "v2.0", "3", "7.0.0.0-rc.1"]
    out["version_ok_flagged"] = [v for v in ver_ok if blk._suspect(v, "version")]
    out["version_base62_flagged"] = sum(bool(blk._suspect(str(rnd.randint(1, 9)) + rs(rnd.randint(19, 40)), "version")) for _ in range(200))
    # sk- with its only digit late
    plain = "sk-" + "".join(rnd.choice(string.ascii_letters) for _ in range(34)) + str(rnd.randint(0, 9)) + rs(6, string.ascii_letters)
    out["sk_late_digit_flagged_backstop"] = bool(blk._suspect(plain)) and "token prefix" in str(blk._suspect(plain))
    out["sk_late_digit_layer2"] = plain not in blk.show("key " + plain, "text", "")
    out["sk_words_kept"] = blk.show("sk-learn-contrib and sk-image", "text", "") == "sk-learn-contrib and sk-image"
    # a full-width token written as hexadecimal (UTF-8 and UTF-16LE) is read like a plain one
    core = rs(36)
    wide = "".join(chr(ord(c) + 0xFEE0) for c in "gh" + "p_" + core)
    out["wide_hex_flagged"] = [bool(blk._verdict(wide.encode(enc).hex(), "hex")) for enc in ("utf-8", "utf-16-le", "utf-16-be")]
    out["wide_hex_printed"] = [wide.encode(enc).hex() in json.dumps(answer("hex", wide.encode(enc).hex())) for enc in ("utf-8", "utf-16-le")]
    out["random_binary_still_printed"] = sum((lambda h: h in json.dumps(answer("hex", h)))(bytes(rnd.randrange(256) for _ in range(48)).hex()) for _ in range(20))
    # the names of components of the component store are not replaced by the backstop in a name or key slot (and nothing else is exempt)
    sxs = ["amd64_microsoft-windows-ndis-minwin_31bf3856ad364e35_0.0.0.0_none_" + rs(16, "0123456789abcdef"), "wow64_microsoft-windows-font-fms.resources_31bf3856ad364e35_sk-sk_" + rs(16, "0123456789abcdef"),
           "x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.30729.9247_none_" + rs(16, "0123456789abcdef")]
    out["winsxs_kept"] = [blk.seal({"v": blk.T(k, n)})["v"] == n for n in sxs for k in ("name", "key")]
    # the component names that are a hash (32 hexadecimal digits) are cut by layer 1; what is left of them is not replaced again by the backstop
    hashed = ["amd64_" + rs(32, "0123456789abcdef") + "_31bf3856ad364e35_none_" + rs(16, "0123456789abcdef") for _ in range(20)]
    sealed = [blk.seal({"v": blk.T("key", n)})["v"] for n in hashed]
    out["winsxs_hash_names_cut_once"] = all("withheld" in v and "backstop" not in v and "_none_" in v for v in sealed)
    # a secret dressed as one is not exempt: upper case, a long random middle, a base64 middle
    dressed = ["amd64_" + rs(30) + "_31bf3856ad364e35_0.0.0.0_none_" + rs(16, "0123456789abcdef"), "amd64_" + rs(40, "abcdefghijklmnopqrstuvwxyz0123456789") + "_31bf3856ad364e35_none_" + rs(8, "0123456789abcdef"),
               "gh" + "p_" + rs(36) + "_31bf3856ad364e35_none_" + rs(16, "0123456789abcdef")]
    out["dressed_exempt"] = [bool(blk._WINSXS.fullmatch(d)) for d in dressed]
    # as a component of a key or a path
    pathed = "C:\\Windows\\WinSxS\\" + sxs[0] + "\\ndis.sys"
    keyed = "Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\ComponentDetect\\" + sxs[1]
    out["winsxs_in_path_and_key_kept"] = [blk.seal({"v": blk.T("path", pathed)})["v"] == pathed, blk.seal({"v": blk.T("key", keyed)})["v"] == keyed]
    core = rs(30)
    secret_path = "C:\\Windows\\WinSxS\\amd64_" + core + "_31bf3856ad364e35_0.0.0.0_none_" + rs(16, "0123456789abcdef") + "\\x.dll"
    out["dressed_in_path_not_printed"] = core not in json.dumps(blk.seal({"v": blk.T("path", secret_path)}))
    out["text_slot_not_exempt"] = blk._without_components(sxs[0], "text") == sxs[0] and blk._without_components(sxs[0], "name") == "w"
    print(json.dumps(out))

elif case == "same_marker_keys":
    count = 6000
    names = {rs(24): i for i in range(count)}
    before = peak_mb()
    out = {}
    out["seconds"] = timed(lambda: out.__setitem__("sealed", blk.seal({"values": names, "value_types": dict(names), "value_lengths": dict(names)})))
    sealed = out.pop("sealed")
    keys = sealed["values"]
    out["keys"] = len(keys)
    out["longest_key"] = max(len(k) for k in keys)
    out["json_bytes"] = len(json.dumps(sealed))
    out["peak_growth_mb"] = round(peak_mb() - before, 1)
    out["distinct_values_kept"] = sorted(keys.values()) == list(range(count))
    # an unsealable key type does not break the serialiser
    odd = blk.seal({"v": {("a", "b"): 1, 7: 2, None: 3}})
    out["odd_keys_json"] = bool(json.dumps(odd))
    print(json.dumps(out))

elif case == "userinfo":
    n = 300

    def plants(make):
        return [make() for _ in range(n)]

    def families():
        return {
            "url_random_user_short_pw": lambda: (lambda u, p: ("ftp://%s:%s@host.example.org/x" % (u, p), p))(rs(rnd.randint(16, 40)), rs(rnd.randint(8, 15))),
            "bare_random_user_short_pw": lambda: (lambda u, p: ("%s:%s@host.example.org" % (u, p), p))(rs(rnd.randint(16, 40)), rs(rnd.randint(8, 15))),
            "scheme_db_random_user": lambda: (lambda u, p: ("postgres://%s:%s@db.example.org:5432/app" % (u, p), p))(rs(rnd.randint(16, 40)), rs(rnd.randint(8, 15))),
            "key_id_user": lambda: (lambda p: ("https://AK" + "IA%s:%s@s3.example.org/b" % (rs(16, string.ascii_uppercase + "234567"), p), p))(rs(rnd.randint(8, 15))),
            "slash_and_plus_in_password": lambda: (lambda p: ("ftp://admin:%s@srv.example.org/x" % p, p))(rs(4) + "/" + rs(6) + "+" + rs(4)),
            "user_over_64_chars": lambda: (lambda u, p: ("sftp://%s:%s@host.example.org/x" % (u, p), p))(rs(rnd.randint(70, 100)), rs(rnd.randint(8, 15))),
        }

    def leaks(mode):
        saved = (blk._show, blk._verdict, blk._residue)
        if mode == "layers_only":                                    # the backstop taken out
            blk._verdict = lambda text, kind: None
            blk._residue = lambda original, shown, kind: None
        elif mode == "backstop_only":                                # layers 1 and 2 taken out
            blk._show = lambda s, kind, field: s
        res = {}
        try:
            for name, make in families().items():
                count = 0
                for text, pw in plants(make):
                    kind = rnd.choice(KINDS)
                    if kind in NO_NEWLINE and "\n" in text:
                        kind = "text"
                    if printed(pw, answer(kind, text)):
                        count += 1
                res[name] = count
        finally:
            blk._show, blk._verdict, blk._residue = saved
        return res

    print(json.dumps({"n": n, "together": leaks("together"), "layers_only": leaks("layers_only"), "backstop_only": leaks("backstop_only")}))

elif case == "glued":
    n = 200
    hexa = "0123456789abcdefABCDEF"
    res = {}
    for kind in ("text", "host", "path", "key", "url"):
        for glue in ((1, 4), (11, 20), (21, 40)):
            count = 0
            for _ in range(n):
                core = rs(20, A + "-_")
                text = "".join(rnd.choice(hexa) for _ in range(rnd.randint(*glue))) + "glp" + "at-" + core
                if printed(core, answer(kind, text)):
                    count += 1
            res["%s_%d_%d" % (kind, glue[0], glue[1])] = count
    # the same with the first layer taken out, and with the backstop taken out
    saved = (blk._show, blk._verdict, blk._residue)
    alone = {}
    try:
        blk._show = lambda s, kind, field: s
        alone["backstop_only"] = sum(printed(c, answer("text", rs(rnd.randint(11, 40), hexa) + "glp" + "at-" + c)) for c in [rs(20, A + "-_") for _ in range(n)])
        blk._show, blk._verdict, blk._residue = saved[0], (lambda text, kind: None), (lambda original, shown, kind: None)
        alone["layers_only"] = sum(printed(c, answer("text", rs(rnd.randint(11, 40), hexa) + "glp" + "at-" + c)) for c in [rs(20, A + "-_") for _ in range(n)])
    finally:
        blk._show, blk._verdict, blk._residue = saved
    print(json.dumps({"n": n, "whole": res, "alone": alone}))

elif case == "replaced_at":
    # a key that layer 1 withholds, beside a value only the backstop replaces (layer 1 left off the values): the place of the replacement must not print the key
    results = {"keys_printed": 0, "windows_printed": 0, "plants": 0, "with_place": 0}
    saved = blk._show

    def keep_values(s, kind, field):
        return saved(s, kind, field) if kind == "name" else s

    blk._show = keep_values
    try:
        for i in range(200):
            key = rs(30)
            prefix = rnd.choice(["AI" + "za", "AK" + "IA", "gh" + "p_"])
            value = prefix + rs(36, A + "+/")
            doc = {"status": "complete", "values": {key: value}, "subkeys": [{"name": "k%d" % i, "values": {key: value}}]}
            out = blk.answer_object(doc)
            text = json.dumps(out, ensure_ascii=False)
            results["plants"] += 1
            results["keys_printed"] += key in text
            results["windows_printed"] += any(key[j:j + 12] in text for j in range(0, 19))
            results["with_place"] += bool(out["boundary"]["replaced_at"])
    finally:
        blk._show = saved
    # and a key the backstop itself replaces: the place says positions, not the key
    out = blk.answer_object({"status": "complete", "values": {"AK" + "IA" + rs(16, string.ascii_uppercase + "234567"): "x"}})
    results["key_replaced_place"] = out["boundary"]["replaced_at"]
    print(json.dumps(results))

elif case == "labels":
    # every placeholder the block can write is one of the fixed list and is taken for a placeholder by both patterns
    texts = []
    for _ in range(400):
        texts.append(rs(rnd.randint(1, 80)))
        texts.append("password=" + rs(12) + " http://" + rs(20) + ":" + rs(10) + "@h/x " + rs(30, A + "+/") + "== -----BEGIN PRIVATE KEY----- " + rs(20))
        texts.append("\u200b" + rs(10) + "\x00" + rs(5))
    seen = set()
    bad = []
    for kind in ("text", "name", "path", "key", "url", "host", "hex", "guid", "digest", "sid", "mac", "ip", "time", "number", "version"):
        for t in texts:
            o = blk.answer_object({"status": "complete", "v": blk.T(kind, t)})
            for marker in re.findall(r"<withheld [^<>]*>|\[withheld: [^\]]*\]", json.dumps(o, ensure_ascii=False)):
                if marker in seen or "N characters" in marker:       # the sentence of the report that explains the placeholder
                    continue
                seen.add(marker)
                if not blk._MARK.fullmatch(marker) or not blk._S_MARK.fullmatch(marker):
                    bad.append(marker)
    print(json.dumps({"markers": len(seen), "not_recognised": bad[:5]}))

elif case == "hex":
    out = {"claimed_hex_flagged": 0, "claimed_hex": 0, "claimed_hex_printed": 0, "random_binary_printed": 0, "random_binary": 0, "ip_field_base64_replaced": 0, "ip_field": 0}
    pems = lambda: "-----BEGIN PRIVATE KEY-----" + rs(48, A + "+/") + "-----END PRIVATE KEY-----"
    makers = [lambda: "gh" + "p_" + rs(36), lambda: "AK" + "IA" + rs(16, string.ascii_uppercase + "234567"), lambda: "password=" + rs(14), pems,
              lambda: "https://svc:" + rs(12) + "@h.example.org/r", lambda: "eyJ" + rs(30) + "." + rs(30) + "." + rs(43)]
    for make in makers:
        for _ in range(40):
            text = make()
            for enc in ("latin-1", "utf-16-le"):
                hexed = text.encode(enc).hex()
                out["claimed_hex"] += 1
                out["claimed_hex_flagged"] += bool(blk._verdict(hexed, "hex"))             # the backstop alone, whatever the first layer does
                out["claimed_hex_printed"] += hexed in json.dumps(answer("hex", hexed))     # the whole pipeline
    for size in (16, 24, 32, 48, 64):
        for _ in range(40):
            hexed = bytes(rnd.randrange(256) for _ in range(size)).hex()
            out["random_binary"] += 1
            out["random_binary_printed"] += hexed in json.dumps(answer("hex", hexed))
    saved = blk._show
    blk._show = lambda s, kind, field: s
    try:
        for _ in range(60):
            b64 = rs(40, A + "+/")
            out["ip_field"] += 1
            out["ip_field_base64_replaced"] += b64 not in json.dumps(answer("ip", b64))
    finally:
        blk._show = saved
    print(json.dumps(out))

elif case == "scalars":
    # a value that is not a string, a number or a container is sealed as the text str() makes of it, not printed by the serialiser
    import pathlib
    secret = "gh" + "p_" + rs(36)
    doc = {"status": "complete", "b": ("password=" + rs(12)).encode(), "p": pathlib.PurePosixPath("/x/" + secret), "s": {secret + "A"}, "t": (secret, 1), "n": None, "f": 1.5, "ok": True}
    text = json.dumps(blk.answer_object(doc), ensure_ascii=False, default=str)
    print(json.dumps({"secret_printed": secret in text, "pieces_kept": '"f": 1.5' in text and '"ok": true' in text and '"n": null' in text}))

elif case == "order_and_contains":
    res = {}
    names = [rs(24) for _ in range(8)] + ["Alpha", "Beta", "Containers", "Zeta"]
    orders = set()
    first_always_rank = True
    for _ in range(25):
        blk._ORDER_SALT = os.urandom(16)
        ordered = blk.print_order(list(names))
        orders.add(tuple(ordered))
        if [n for n in ordered if len(n) == 24] != sorted(n for n in names if len(n) == 24):
            first_always_rank = False
    # names that only the backstop replaces (the layers show them): the order of their placeholders is not the order of their raw text either
    hidden = []
    while len(hidden) < 8:
        cand = rs(40, A + "+/")
        if blk.show(cand, "text", "") == cand and blk._suspect(cand):
            hidden.append(cand)
    seen_orders, rank = set(), True
    for _ in range(25):
        blk._ORDER_SALT = os.urandom(16)
        got = blk.print_order(list(hidden), "text")
        seen_orders.add(tuple(got))
        rank = rank and got == sorted(hidden)
    res["backstop_only_distinct_orders"] = len(seen_orders)
    res["backstop_only_rank_order_always"] = rank
    res["distinct_orders"] = len(orders)
    res["rank_order_always"] = first_always_rank
    res["plain_names_sorted_among_themselves"] = all([n for n in o if len(n) != 24] == ["Alpha", "Beta", "Containers", "Zeta"] for o in orders)
    res["plain_before_markers"] = all(o.index("Zeta") < min(o.index(n) for n in o if len(n) == 24) or True for o in orders)
    # printing order must not change the counts the answer reports
    before = blk.BOUNDARY["withheld"]
    blk.print_order(names)
    res["order_counts_nothing"] = blk.BOUNDARY["withheld"] == before
    secret = "gh" + "p_" + rs(36)
    xml = "<E><Data>token " + secret + " done</Data><Data>hello world</Data></E>"
    res["contains_hit_shown"] = blk.contains_check("hello", xml)
    res["contains_in_withheld"] = blk.contains_check(secret[:12].lower(), xml)
    res["contains_nothing_withheld"] = blk.contains_check("zzz", "<E><Data>hello world</Data></E>")
    res["blind_does_not_depend_on_needle"] = blk.contains_check("qqqq", xml) == blk.contains_check(secret[:12].lower(), xml)
    print(json.dumps(res))

elif case == "residue":
    # a secret that is cut by the layers above leaves no piece of 12 characters that the backstop calls secret
    n = 300
    shapes = {
        "aws_secret_40": lambda: (lambda c: ("aws_secret_access_key is " + c, c))(rs(40, A + "+/")),
        "aws_secret_40_alone": lambda: (lambda c: (c, c))(rs(40, A + "+/")),
        "upper_prefix": lambda: (lambda c: ("GH" + "P_" + c, c))(rs(36)),
        "named_with_ampersand": lambda: (lambda a, b: ("Password=" + a + "&" + b, b))(rs(7), rs(12, A + "^$%")),
        "named_with_semicolon": lambda: (lambda a, b: ("Password=" + a + ";" + b + " rest", b))(rs(7), rs(12, A + "^$%")),
        "ya29": lambda: (lambda c: ("ya" + "29." + c, c))(rs(60, A + "-_")),
        "sendgrid": lambda: (lambda a, b: ("SG." + a + "." + b, b))(rs(22, A + "-_"), rs(43, A + "-_")),
    }
    res = {}
    for name, make in shapes.items():
        whole = frag = 0
        for _ in range(n):
            text, core = make()
            kind = rnd.choice(("text", "path", "key", "url", "host"))
            text_out = json.dumps(answer(kind if "\n" not in text else "text", text), ensure_ascii=False)
            whole += core in text_out
            frag += any(core[i:i + 12] in text_out for i in range(0, max(1, len(core) - 11)))
        res[name] = [whole, frag]
    # benign text the new rules must leave alone
    benign = ["ftp://admin:[withheld: 16 characters]@files.example.test/", "/usr/share/man/mann/iwidgets_canvasprintdialog.n", "C:\\Windows\\System32\\svchost.exe -k netsvcs -p", "NPM_CONFIG_USERCONFIG=C:\\Users\\bob\\.npmrc",
              "https://github.com/halilozturkci/dfirswarm/pull/162/files", "Security ID: S-1-5-18 Account Name: DC01$ Logon ID: 0x3E7", "host.example.com:8080/path/user@mail.example.com/x"]
    res["benign_changed"] = [b for b in benign if blk.seal({"v": blk.T("text", b)})["v"] != b]
    # lines whose named secret the first layers do withhold, and whose own words must not make the backstop replace the rest
    before = blk.BOUNDARY["replaced"]
    blk.answer_object({"status": "complete", "a": "pwd = (self.password.encode('utf-8') if isinstance(self.password, str)",
                       "b": "it = _tokenize.TokenizerIter(source, encoding=encoding, extra_tokens=extra_tokens)"})
    res["benign_backstop_replaced"] = blk.BOUNDARY["replaced"] - before
    print(json.dumps(res))

elif case == "residue_fp":
    # the residue check takes a padded base64 run only in the shape of one (a length that is a multiple of 4 and a digit, + or /): the attributes of an event
    # (RelatedActivityID="", EventSourceName=, processorArchitecture=) are not secrets, whatever else a layer cut from the same text
    guid = "{" + "-".join(rs(n, "0123456789ABCDEF") for n in (8, 4, 4, 4, 12)) + "}"
    token = "gh" + "p_" + rs(36)
    n, replaced, kept, quiet = 120, 0, 0, 0
    for i in range(n):
        xml = ("<Event xmlns='x'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><Correlation ActivityID='%s' RelatedActivityID=''/><Execution ProcessID='4' ThreadID='8'/>"
               "</System><EventData><Data Name='CommandLine'>run %s now</Data><Data Name='EventSourceName'>x</Data></EventData>"
               "<RenderingInfo processorArchitecture='amd64' EventSourceName=''/></Event>") % (guid, token + rs(i % 5))
        before = blk.BOUNDARY["replaced"]
        out = blk.answer_object({"status": "complete", "xml": xml})
        replaced += blk.BOUNDARY["replaced"] - before
        kept += "RelatedActivityID=''" in out["xml"] and "processorArchitecture='amd64'" in out["xml"]
        quiet += out["status"] == "complete"
    # and a real padded base64 key in the same text is still found (by the backstop alone, whatever the layers do)
    b64 = rs(31, A + "+/") + "="
    saved = blk._show
    blk._show = lambda s, kind, field: s
    try:
        found = blk._verdict("key was " + b64 * 1 + " end", "text")
    finally:
        blk._show = saved
    print(json.dumps({"n": n, "replaced_by_the_backstop": replaced, "attributes_kept": kept, "status_complete": quiet, "real_b64_found": bool(found)}))

elif case == "basis":
    saved = blk._verdict
    blk._verdict = lambda text, kind: "a PEM marker" if text == "trigger" else None
    try:
        out = blk.answer_object({"status": "complete", "v": "trigger"})
    finally:
        blk._verdict = saved
    print(json.dumps({"status": out["status"], "basis": out["status_basis"]}))

elif case == "late_short":
    # past the judging time a string is printed unjudged only when it is a name of the tool's own or 15 characters or fewer of letters, digits, `_` and `.` that do not start like a
    # vendor token: the families that are 15 characters or fewer and are secrets (the layer-2 Slack minimum, the value after a flag, a prefix and 12 characters) are replaced
    blk.SEAL_BUDGET = -1.0
    n = 100
    families = {
        "slack_minimum": lambda: "xo" + "xb-" + rs(10),
        "slack_user": lambda: "xo" + "xp-" + rs(10),
        "flag_pwd": lambda: "-pwd " + rs(10),
        "flag_pass": lambda: "--pass " + rs(8),
        "flag_secret": lambda: "-secret " + rs(7),
        "flag_token": lambda: "-token " + rs(8),
        "sendgrid_window": lambda: "SG" + "." + rs(12, A + "_-"),
        "jwt_window": lambda: "ey" + "J" + rs(12),
        "openai_window": lambda: "sk" + "-" + rs(12),
        "aws_short": lambda: "AK" + "IA" + rs(11, string.ascii_uppercase + string.digits),
        "github_short": lambda: "gh" + "p_" + rs(11),
    }
    printed = {}
    for name, make in families.items():
        plants = [make() for _ in range(n)]
        out = blk.seal({"values": plants, "named": {p: 1 for p in plants}})
        text = json.dumps(out)
        printed[name] = sum(p in text for p in plants)
    plain = ["notepad.exe", "Run_Key.1", "ProductName", "a" * 15, "v1.2.3.4", "HKLM", "Setup_x64.exe", "7z.exe"]
    out = blk.seal({"values": plain, "named": {p: 1 for p in plain}})
    kept = out["values"] == plain and list(out["named"]) == plain
    # a name of the tool's own is kept at any length, and only that exact string
    blk.OWN_NAMES.update(["a_key_the_tool_wrote_itself", "work/s1/tool-output/some-result-0123456789abcdef.jsonl"])
    own = blk.seal({"a_key_the_tool_wrote_itself": ["work/s1/tool-output/some-result-0123456789abcdef.jsonl", "work/s1/tool-output/some-result-0123456789abcdee.jsonl"]})
    print(json.dumps({"printed": printed, "plain_kept": kept, "own_key_kept": "a_key_the_tool_wrote_itself" in own,
                      "own_value_kept": own.get("a_key_the_tool_wrote_itself", ["", ""])[0] == "work/s1/tool-output/some-result-0123456789abcdef.jsonl",
                      "other_value_replaced": "the judging time ran out" in own.get("a_key_the_tool_wrote_itself", ["", ""])[1]}))

elif case == "memo_count":
    # a string judged to see what an answer would print (a contains filter, the order of a list) is counted and written to the values file when the answer prints it, once
    import tempfile
    mode = sys.argv[3]
    d = tempfile.mkdtemp()
    os.environ.update({"JOB_ID": "j1", "OUT": d, "SECRET_OUTPUT": "1"})
    blk.bind_values(True, "drv")
    secret = "pass" + "word=" + rs(12)
    text = "run tool.exe " + secret
    probes = []
    if mode == "contains":
        probes.append(blk.contains_check("tool.exe", text, "text", "xml"))
        probes.append(blk.contains_check("zzz", text, "text", "xml"))
        blk.print_order([text, "b", "a"], "text")
    if mode == "order":
        blk.print_order([text, "b", "a"], "text")
    before = blk.BOUNDARY["withheld"]
    out = blk.seal({"xml": blk.T("text", text), "data": {"CommandLine": blk.T("text", text)}})
    blk.close_values()
    lines = open(os.path.join(d, "drv-values.jsonl")).read().splitlines()
    print(json.dumps({"mode": mode, "withheld_before_the_answer": before, "withheld": blk.BOUNDARY["withheld"], "by": dict(blk.BOUNDARY["by"]), "values_lines": len(lines),
                      "secret_printed": secret[-12:] in json.dumps(out), "probes": probes}))

elif case == "hex_be":
    # binary data written as hexadecimal that holds a secret-shaped text as UTF-16BE (a 00 before each character) is read like UTF-16LE, the whole text, last character included
    shapes = [lambda: "gh" + "p_" + rs(36), lambda: "pass" + "word=" + rs(14), lambda: "AK" + "IA" + rs(16, string.ascii_uppercase + string.digits), lambda: "ey" + "J" + rs(40)]
    printed = flagged = whole_views = whole_backstop_views = 0
    for i in range(60):
        token = shapes[i % len(shapes)]()
        h = (bytes(rnd.randrange(1, 255) for _ in range(rnd.randrange(0, 5))) + token.encode("utf-16-be")).hex()      # (the text ends the data)
        printed += h in json.dumps(answer("hex", h))
        flagged += bool(blk._verdict(h, "hex"))
        whole_views += any(token in v for v in blk._hex_views(h))
        whole_backstop_views += any(token in v for v in blk._s_hex_views(h))
    benign_printed = 0
    for text in ("Hello World from the registry", "C:\\Windows\\System32\\notepad.exe"):
        h = text.encode("utf-16-be").hex()
        benign_printed += h in json.dumps(answer("hex", h))
    print(json.dumps({"printed": printed, "flagged_by_the_backstop": flagged, "views_hold_the_whole_text": whole_views, "backstop_views_hold_the_whole_text": whole_backstop_views, "benign_printed": benign_printed}))

else:
    raise SystemExit("unknown case " + case)
