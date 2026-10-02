---
network: closed
policy: ctf
more_evidence: no
premises:
  - This is a synthetic offline CTF. The supplied memory image is presented as Carmine Falcone's laptop memory, and unknown.data is the additional handout evidence. Their actual contents and recoverability remain to be examined.
---
## Goal

Solve Batman Investigation II (Gotham Underground Corruption) from the two supplied evidence files. Establish all 14 exact answers from evidence. No solution, write-up, previous case run, author repository, online search or external challenge material may be read or requested. External systems named in the evidence are never contacted. Suspicious files are examined as bytes and never executed. Passwords and private keys recovered here belong to a synthetic CTF and are required answers; include them only as needed to demonstrate the requested answer.

## Evidence

Only these original handout members are supplied under read-only `inputs/`:
- `chall/Carmine-Falcone.raw` (4,831,838,208 bytes)
- `chall/unknown.data` (36,194 bytes)

Use `inputs` to obtain the exact mounted paths. Read offsets and ranges or stream large scans; do not load the entire 4.8 GB dump into a Python bytes object. Preserve offsets, encoding, hashes and extraction/decryption commands for every claim. Do not edit the originals.

## Tool readiness

The memory image has Volatility 3, MemProcFS and the memory-forensics pack. The operator has supplied the precise Windows kernel ISF derived from Microsoft's matching PDB as tool reference data. For Volatility use `vol --offline -s /tmp/dfirswarm-batman-ii-preparation/home/packs/memory-forensics/vendor/symbols -f <actual-input-path> <plugin>` (the pack directory is mounted read-only). The source/digest is recorded separately. This is a kernel description, not case evidence or an answer. Network stays closed apart from the model provider. Tools may be forged from your own code; tool jobs run offline. Check what is actually available before relying on it. If any program or reference is missing, state the precise requirement on the board for the operator.

## Questions

1. who asked Carmine falcon to contact someone and who is falcone disguised as?
   Format: `disguse-name_person-contacted (all lowercase)`

2. what is the hash of the file that he sent him to contact
   Format: `sha1sum`

3. what is the password of his password manager
   Format: `password_manager_name_with_version:md5(password)`

4. what is the key he stored in his password manager that he deleted?
   Format: `(format: user_name:key)`

5. what is the cryptocurrency wallet installed and when is it installed?
   Format: `wallet_name-date-time(in format YYYY:MM:DD:HH:MM)`

6. what is the malware that wants to steal the cryptocurrency wallet and ip it's trying to send to with port number?
   Format: `malware_ip:port)`

7. Eventhough Falcone's Network Moniter blockked the file sent, falcone made sure to zip with a password and noted it down temproarily in his screen and sent it to a detective for analysis.what is the password of the zip file?
   Format: `md5(password)`

8. what is the hash of the original files in the zip file before the stealer modified them?
   Format: `sha1sum:sha1sum`

9. what is the password that Carmine Falcone protected the wallet with
   Format: `md5(password)`

10. who did Carmine falcone recive money from?
   Format: `name_person:curreny_used(3 or 4 letter significance):amount(in dollars with precision of 2 decimal places):transaction_id`

11. who did Carmine falcone send money to?
   Format: `name_person:curreny_used(3 or 4 letter significance):amount(in dollars with precision of 2 decimal places):addres`

12. what is the name and client private key that Salvatore asked for contact verification?
   Format: `infobreakage_dbkey:client_email`

13. what is the information interpreted further from previous question
   Format: `name_client:private_key`

14. what is the userkey of the encrypted dbx database?
   Format: `userkey`

## Must establish

- 1
- 2
- 3
- 4
- 5
- 6
- 7
- 8
- 9
- 10
- 11
- 12
- 13
- 14

## Working method

All ten agents participate; read team.json, introduce your model and present focus on the board, claim leads before expensive work, and coordinate discovery yourself. Choose a report author and a different critic. Share sealed outputs and precise byte locators so another agent can independently re-derive the result. Avoid repeating large scans already completed or running; read the job list and board first. A tool's zero exit, a matching string, consensus, a hash shape or a passed mechanical gate is not proof of the answer.

For each question record findings with resolvable refs, an `answer` with `section=question:<n>` and `result=established`, and an independent peer's `attest` or justified `dispute`. The critic states what was reproduced from bytes, what was only read, alternative explanations and contradictions. Revise false candidates. A partial answer, absence, premise rejection, best candidate, scope change or accepted limit does not solve this CTF. Do not withdraw or relax the questions. Continue until each exact requested value is supported. Ask the operator when a concrete resource is needed; do not invent an answer.

## Definition of done

1. All 14 exact answers are established, with reproducible evidence and independent review. Any uncertainty stays explicit and keeps the investigation open.
2. `work/report.md` has numbered headings `## 1.` through `## 14.`, each answer, byte/process/file locator, derivation, ledger refs, contrary evidence and review. Also write a timeline and reconstruction explaining how the artifacts fit.
3. `work/answers.json` is a JSON object with exactly keys "1" through "14". Each value is an object with `answer` (exact formatted string), `status` ("established"), `support` (nonempty array of E-<seq> strings), `author` and `reviewer` (different assigned agent ids). Maintain this only from reviewed ledger answers; never put a guess or placeholder in it.
4. When all answers and reviews are ready, post their artifact and ledger refs to the operator. Derive a final flag from evidence if the handout itself explains one; never fetch a flag recipe or solution. The operator independently checks final challenge completion outside the agent boundary. Keep investigating discrepancies rather than claiming the checks are a correctness oracle.
5. Original inputs are unchanged and no forbidden source has been accessed.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14; do grep -q "^## $n\." work/report.md || exit 1; done`
- `python3 -c 'import json; d=json.load(open("work/answers.json")); assert set(d)=={str(i) for i in range(1,15)}; assert all(isinstance(v,dict) and v.get("status")=="established" and isinstance(v.get("answer"),str) and v["answer"].strip() and v.get("support") and v.get("author") and v.get("reviewer") and v["author"]!=v["reviewer"] for v in d.values())'`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6,7,8,9,10,11,12,13,14`
