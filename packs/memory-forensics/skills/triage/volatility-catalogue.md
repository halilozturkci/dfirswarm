---
id: triage/volatility-catalogue
title: The kickoff's plugin catalogue and its limits
when: The memory-windows recipe ran at the kickoff and you read its receipts.
needs: []
tools: []
requires_host: []
---

Use only if the kickoff's catalogue is on and the base pack's `memory-windows` recipe has run. Not for running plugins yourself (`triage/volatility`).

**The kickoff's catalogue.** When it is on, the base pack's `memory-windows` recipe
has run `windows.info` and a baseline of plugins: read its receipts, and
`catalog/missing.json`, which names the kernel when the image lacks its table. Its
detection is a bounded Windows probe, not a check of every platform or plugin. As of
this revision the recipe runs Volatility with `--offline` at every step and, when the
image lacks the table, stops after `windows.info` with coverage partial; it fetches
nothing (its `run.sh` and `recipe.json` say so). This skill's rule stands either way:
you do not run a fallback that fetches. Inspect the executed command (`steps.jsonl`)
and the coverage text before you describe any recipe output as offline, and say when
it was not.

**Does not show.** That a baseline of plugins is the whole examination; that a recipe's output was offline without its executed command and coverage text saying so; that a Windows probe checked another platform.

Sensitive output: the recipe's plugin output can hold what `triage/volatility` names (command lines, environments); keep it sealed and cite receipts, not content.
