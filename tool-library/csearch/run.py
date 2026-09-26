import json, sys, os, re
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[0]).resolve().parents[1]))
from _output import LosslessPage

ROOT = os.getcwd()
CAT = {
    "filelist": "catalog/s4a-challenge4/p2048/filelist.txt",
    "timeline": "catalog/s4a-challenge4/p2048/timeline.csv",
    "bodyfile": "catalog/s4a-challenge4/p2048/bodyfile.txt",
    "pslist": "catalog/memdump.mem/pslist.txt",
    "psscan": "catalog/memdump.mem/psscan.txt",
    "cmdline": "catalog/memdump.mem/cmdline.txt",
    "netscan": "catalog/memdump.mem/netscan.txt",
    "malfind": "catalog/memdump.mem/malfind.txt",
    "dlllist": "catalog/memdump.mem/dlllist.txt",
}

def main():
    data = json.load(sys.stdin)
    patterns = data.get("patterns") or []
    files = data.get("files") or ["filelist", "timeline"]
    insensitive = data.get("insensitive", True)
    max_lines = int(data.get("max_lines", 200))
    regex = data.get("regex", False)
    catalog_root = data.get("catalog_root")

    if not patterns:
        print("error: patterns required", file=sys.stderr)
        sys.exit(2)

    flags = re.IGNORECASE if insensitive else 0
    if regex:
        matchers = [re.compile(p, flags) for p in patterns]
    else:
        matchers = [re.compile(re.escape(p), flags) for p in patterns]

    out = LosslessPage(
        "csearch",
        [catalog_root, files, patterns, insensitive, regex],
        max_lines,
    )
    for key in files:
        if key not in CAT:
            print(f"error: unknown catalog key '{key}'", file=sys.stderr)
            sys.exit(2)
        rel = CAT[key]
        if catalog_root:
            rel = os.path.join(str(catalog_root), os.path.basename(rel))
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            print(json.dumps({"error": f"catalog file not found: {rel}"}))
            sys.exit(1)
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if any(m.search(line) for m in matchers):
                    text = line.rstrip("\n")
                    out.add(f"[{key}] {text}")

    page = out.finish()
    if not out.page:
        print("(no matches)")
    else:
        print("\n".join(out.page))
    if page.get("all_results"):
        print(
            f"{page['matched']} lines matched; showing {page['returned']}; "
            f"all results: {page['all_results']} ({page['all_results_format']})",
            file=sys.stderr,
        )

if __name__ == "__main__":
    main()
