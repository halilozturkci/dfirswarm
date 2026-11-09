### Fixed: beacon_score reads its arguments within a bound and under a clock

- A series passed inline is refused before the arguments are parsed when they hold more than 504,096 commas (the 500,000-event cap and 4,096 for the
  other parameters), so the cap holds before a large list is built whole. A 32 MiB list of `0.5,` peaked at 88 MB resident where parsing it took
  402 MB (Linux, the child's own peak); the refusal names the number of commas and says to use `timestamps_file`.
- Standard input is read in a loop under the tool's own clock (45 seconds, under the manifest's 60): a writer that never closes it now ends the call as
  a JSON refusal, and a stop signal during the wait still ends it with partial JSON and exit 143. The manifest says so.
- `timestamps_file` is opened without blocking and its type is read from the descriptor, so a name that turned into a pipe since the first check is refused instead of waited on.
- Packs: network-forensics (`beacon_score`).
