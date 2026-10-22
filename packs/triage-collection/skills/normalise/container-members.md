---
id: normalise/container-members
title: Container identity when members become files
when: A delivery is an archive, or a tree extracted from one.
needs: [evidence/archives]
tools: [archive_extract, collection_manifest_verify]
requires_host: []
---

Use when a collector's output arrives as a zip or tar, or you extracted one. Not for the archive's own safety rules (`evidence/archives`) or for source paths (`normalise/layout`).

1. Inventory before you extract. The `collection-intake` recipe reads a zip or tar (no other format) in one pass and extracts nothing: every member with its number `n`, kind and SHA-256, the collector's records as canonical rows, and one verification row per delivery claim. The base `archive-members` recipe lists any archive's members with the exact name bytes (`path_b64`), sizes, times, link targets and flags. Keep `n`: the same number is `archive_extract`'s `from_index`.
2. Keep what a tree no longer shows: the original name bytes (a name that is not UTF-8 is renamed on some file systems), duplicate names (two members, two rows), links and devices (not recreated; each is a row with its target), sparse representations, extended attributes, and each member's compression or encryption state. A partial listing, an unreadable member or a member over a budget is a stated limit, not a missing file.
3. Follow one chain per file, container to member to extracted object, and cite it by the container's hash, the member's `n` and the extracted job path. Two members that extract to one path are a collision: say which one the file is.
4. A nested archive or image is named (`looks_like`, `nested_archives`), never opened by the first pass. Extract it in a call of its own with its own budgets and classify what it holds separately; a disk image inside a collection is not a logical collection.
5. After extraction run `collection_manifest_verify` on the extracted tree. The recipe's verification judges the archive's members; the tool judges the extracted files. Where both agree on a file, the extraction preserved it; where they differ, the extraction or the copy changed it, which the two results together can say and neither alone can.
6. The archive's own member times are one clock, the extracted files' times another (`verify/time-layers`).

Shows: which member became which file, and which limits applied to the listing and the extraction. Does not show: that the archive is authentic or complete as acquired, that a member's stored time is real, or that an absent member was never collected.
Record: the container hash, the member numbers and names (or `path_b64`), the extraction budgets and `stopped_by`, and each nested archive left unopened.
Sensitive output: members may hold credential stores; run the extraction and the verification as jobs with `secret_output: true`, cite a member by `n` and its place, never by its text or the digest of a secret file.
