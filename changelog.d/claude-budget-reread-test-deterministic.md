### Fixed: the budget re-read test no longer depends on how fast the machine is

The dry-run test that checks a fold reads a `budget.json` caught mid-save once more before refusing it failed once on a loaded CI runner ("budget.json does not read (Unexpected end of JSON input)"). It left the file empty and let a 20 ms timer write the content back, while the fold waits 100 ms before its second read; on a starved runner the second read could land before the write finished. It is a test change only; the fold is unchanged.

- The finished save is now released by the fold's own first read of `budget.json` (a spy on `readFile`) and written whole, a temp file and a rename, so the first read always sees the half-saved file and the second always sees the finished one, whatever the machine does between them.
- The test also asserts that the fold read the file exactly twice, so it still fails if the second read is taken out of the fold (checked by removing it).
