---
id: scripts/static-analysis
title: PowerShell, JavaScript and VBScript read as evidence
when: A recovered script must be read, decoded or described without being run.
needs: [triage/quarantine]
tools: [ioc_scan]
requires_host: [strings]
---

Use when a script (PowerShell, JavaScript, VBScript or a Windows Script Host file) has been recovered and you must describe it. Not for running it, pasting it into an interpreter to tidy it, fetching anything it names, or saying who wrote it or why.

1. **Identify language, host and encoding before reading.** The text implies a host, and that is a claim: `WScript.Shell` or `ActiveXObject` points at Windows Script Host, `require(` at Node, `document.` or `window.` at a browser, cmdlets and `param(` at PowerShell. Check for a byte-order mark and for UTF-16LE (`strings -a -e l -t x SAMPLE` finds it); record the encoding you read it in.
2. **Keep source spans.** Cite the line and column (or byte offset) in the file you read, and for every derived text the offset in its parent. A paraphrase without a span is not evidence.
3. **Decode data with transformations that do not evaluate.** A PowerShell `-EncodedCommand` value is base64 of UTF-16LE text; Deflate and gzip streams are data; decode them in a job with a standard-library decoder that does not evaluate (`strings/decoding-and-similarity`), write the result to `$OUT`, and record the input range, the sequence of steps and the output file. The result is data, never code you ran.
4. **Stop at the first layer you can only resolve by evaluating the script's own code.** Concatenation and escapes can be read; a value built by `eval`, `Invoke-Expression`, `Function(` or `new ActiveXObject` arguments at run time cannot. Record the unresolved expression with its span and say it is unresolved.
5. **A call is a conditional capability.** `DownloadString`, `XMLHttpRequest`, `Start-Process` or `CreateObject("WScript.Shell")` in the text says the script can ask for that, under a host that provides it, if that line is reached. It does not show a connection or a process: that comes from process, script-block or proxy artefacts, in the Windows or network pack if one is loaded (check the run's tool inventory).
6. **Never contact an indicator.** URLs, hosts and paths found are strings with spans; look for them with `ioc_scan` in the corpus, and keep them out of any fetch.
7. **No parse-only tooling is declared** beyond the standard library: do not use a generic interpreter as a "safe" parser, and do not build one from the script's source.

Sensitive output: scripts hold credentials, tokens and URLs with user-info. Decode and read in a job with `secret_output: true`; cite span and length, not the value, a fragment or a hash.

Shows: what the text says, at spans, after recorded transformations. Does not show: that any line ran, what it fetched or changed, or the author's purpose. Record: language and host evidence, encoding, spans, each transformation with input and output files, the unresolved expressions.
