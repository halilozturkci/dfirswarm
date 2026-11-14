---
id: data/http-cache
title: HTTP cache bodies
when: A file a Chromium browser cached is needed.
card: cache_body: {"path": "<16 hex>_0"} writes one simple-cache entry's body out, decoded; a block-file cache DIRECTORY is listed first ({"path": "<dir>", "list": true}), then {"path": "<dir>", "entry": n} or {"address": "0x..."}; a plain file stored with brotli needs {"encoding": "br"}. partial with "brotli: not decodable here" means the body file is STILL compressed: nothing in it speaks for the page. The key (the URL), the headers and the body are files, never in the answer. An entry shows bytes were stored under a key, not that a person opened the page.
needs: []
tools: [cache_body]
requires_host: []
---

Use when the content a Chromium browser or an Electron app cached (a page, a script, an image, a download's first copy) is needed as a file. Not for history or cookies (`data/sqlite`), IndexedDB and Local Storage (`data/browser-storage`), or the cache of Firefox or Safari, which `cache_body` does not read.

    job_run tool=cache_body args={"path": "work/<you>/Cache_Data/<16 hex>_0"}
    job_run tool=cache_body args={"path": "work/<you>/Cache", "list": true}

1. **Which cache.** A simple cache is a folder of `<16 hex>_0` files: each is one entry, read directly. A block-file cache is a folder with `index`, `data_0` to `data_3` and `f_` files: give the folder, list it (`entries.tsv`: `n`, `address`, sizes, `created_utc`, `key`), then take one entry by `entry` or `address`. A lone `f_` file or a carved response is a plain file.
2. **Read `status` and `encoding`.** The stored response's `Content-Encoding` says how the body is kept. gzip and deflate are always decoded; brotli and zstd only where a Python module imports (brotli 1.2 or later); several codings at once are not decoded. `partial` with "brotli: not decodable here" means the body file is still compressed: a search of it finding nothing is no negative. A plain file has no header: brotli needs `encoding: "br"`.
3. **Check the entry's own checks:** `stored_crc32_matches` and `key_sha256_matches` say whether the stored bytes are whole; either false, `checks: none`, `response.truncated` (an unfinished response), a `Content-Length` other than the stored size, a `decode_error`, `bytes_after_the_stream_end`, `truncated` (cut at `max_bytes`: the file holds `decoded_bytes`) or a `signature_note` (gzip bytes no header names) makes the answer `partial`. So is a list whose index count differs from its table.
4. **The type is a reading of the first bytes** (`detected_type`), not a validation; compare it with the response's `content_type`, and say when they disagree.
5. **Time.** `created_utc` (block-file) is the browser's clock when the entry was made, in UTC; a simple-cache entry file carries no time of its own (`timeline/clocks`).

**Record.** The entry file or the cache folder and `address`, the body file and its sha256, the coding and who said it, `status`.

**Shows.** That these bytes were stored under this key by this profile. **Does not show.** That a person opened the page, when it was shown, what the server serves now, or an entry the cache has evicted.

**Sensitive output.** The key, the headers and the body can hold session tokens and personal content: they are files, never in the answer. When the case turns on them, run the job with `secret_output: true` and cite the file.
