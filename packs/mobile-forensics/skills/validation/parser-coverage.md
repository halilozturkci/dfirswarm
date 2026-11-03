---
id: validation/parser-coverage
title: Validating a mobile parser result
when: A LEAPP or other parser result will back a finding, and you must say what it covered.
needs: []
tools: [sqlite_query]
requires_host: []
---

Use when a parser's output will back a finding. Not for the general method of validating a tool (the base pack's tool-validation and coverage notes; read them if you have not).

**Build the matrix** before you read a row: operating-system build by app and schema by parser module. An empty cell is not an empty phone.

**Read the receipt.** `modules.tsv` of `ios-ileapp`, `android-aleapp` and `android-backup-apps` gives one outcome per module, and each means something different:
- `completed`: it ran and reported records or none.
- `no_record`: no source file or no data in this input; never "the artefact is absent from the phone".
- `unsupported`: the module's own gate does not take this build; it read nothing.
- `errored`, `errors_logged`, `unknown`: not covered, whatever the other modules wrote.

**Validate a material row** against the record under it: open the source database with `sqlite_query` on a copy, find the row by its key, and compare the value and the time. Check one row of each kind you will cite. A module you did not validate is a lead.

Shows: which parts of the input a parser read, and that a cited row matches its source.

Does not show: that an artefact is absent, or that an unvalidated module is right.

Record: parser, version, input, the matrix cell, the receipt line, the row you checked.

Sensitive output: a checked row holds message text, accounts or positions; cite its key and keep the values in the case file.
