import json, sys, os, re
from pathlib import Path

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        agent = re.sub(
            r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
        )
        self.path = Path("work") / agent / "tool-output" / f"{self.tool}-{digest}.jsonl"

    def _write(self, row: object) -> None:
        assert self._out is not None
        self._out.write(json.dumps(row, ensure_ascii=False, default=str))
        self._out.write("\n")

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(
                dir=self.path.parent, prefix=f".{self.path.name}-"
            )
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            assert self._tmp is not None
            os.replace(self._tmp, self.path)
            result["all_results"] = str(self.path)
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

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
