#!/usr/bin/env python3
"""Make an archive-only copy of the pinned redactor with indexed digest probes.

Production files, the interrupted original, and agents are unchanged. This
only avoids scanning large text once for every sensitive digest. Replacement
order and the original token, withhold, and final leak-scan logic stay intact.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

original, destination = map(Path, sys.argv[1:3])
text = original.read_text()
start = text.index('  const digestList = [...sensitiveDigests];')
end = text.index('  let files = 0;', start)
replacement = r'''  const digestList = [...sensitiveDigests];
  // Every overlapping lower-case 64-hex substring, including longer runs.
  const digestOccurrences = (text: string): Array<{ start: number; sha: string }> => {
    const found: Array<{ start: number; sha: string }> = [];
    for (const match of text.matchAll(/[0-9a-f]{64,}/g)) {
      const run = match[0];
      for (let offset = 0; offset <= run.length - 64; offset += 1) {
        const candidate = run.slice(offset, offset + 64);
        if (sensitiveDigests.has(candidate)) found.push({ start: match.index! + offset, sha: candidate });
      }
    }
    return found;
  };
  const hasKnownDigest = (text: string): boolean => digestOccurrences(text).length > 0;
  const replaceDigests = (text: string, replaced: Replaced[]): string => {
    const original = (): string => {
      let t = text;
      for (const sha of digestList) {
        if (!t.includes(sha)) continue;
        const id = hideDigest(sha, "the digest of a sensitive output");
        const count = t.split(sha).length - 1;
        t = t.split(sha).join(id);
        replaced.push({ what: "text", entry: null, sha256_of_original: id, count, why: "the digest of a sensitive output" });
      }
      return t;
    };
    const occurrences = digestOccurrences(text);
    if (!occurrences.length) return text;
    // Simultaneous replacement is identical only when matches don't overlap
    // and the replacements introduce no further known digest. Otherwise use
    // the original ordered implementation unchanged.
    for (let i = 1; i < occurrences.length; i += 1) {
      if (occurrences[i].start < occurrences[i - 1].start + 64) return original();
    }
    const counts = new Map<string, number>();
    for (const item of occurrences) counts.set(item.sha, (counts.get(item.sha) ?? 0) + 1);
    const ids = new Map<string, string>();
    for (const sha of digestList) if (counts.has(sha)) ids.set(sha, hideDigest(sha, "the digest of a sensitive output"));
    const pieces: string[] = [];
    let position = 0;
    for (const item of occurrences) {
      pieces.push(text.slice(position, item.start), ids.get(item.sha)!);
      position = item.start + 64;
    }
    pieces.push(text.slice(position));
    const result = pieces.join("");
    if (hasKnownDigest(result)) return original();
    for (const sha of digestList) if (counts.has(sha)) {
      replaced.push({ what: "text", entry: null, sha256_of_original: ids.get(sha)!, count: counts.get(sha)!, why: "the digest of a sensitive output" });
    }
    return result;
  };
'''
text = text[:start] + replacement + text[end:]
replacements = {
    'digestList.some((d) => text.includes(d))': 'hasKnownDigest(text)',
    'digestList.some((d) => l.includes(d))': 'hasKnownDigest(l)',
}
for before, after in replacements.items():
    assert text.count(before) == 1, before
    text = text.replace(before, after)
# Resolve imports to the unchanged repository modules, outside the temp copy.
def absolute(m):
    return m[1] + m[2] + str((original.parent / m[3]).resolve()) + m[2]
text = re.sub(r'''(from\s+|import\(\s*)(["'])(\.\.?/[^"']+)\2''', absolute, text)
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text(text)
destination.chmod(0o600)
print(json.dumps({'source_sha256': hashlib.sha256(original.read_bytes()).hexdigest(),
                  'archive_only_copy_sha256': hashlib.sha256(destination.read_bytes()).hexdigest(),
                  'production_source_modified': False}))
