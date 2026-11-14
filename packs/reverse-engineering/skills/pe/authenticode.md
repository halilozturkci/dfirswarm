---
id: pe/authenticode
title: Reading authenticode_verify and what a verified signature supports
when: A PE signature must be checked, or authenticode_verify's answer must be read.
needs: [triage/quarantine]
card: Trust comes only from the call: authenticode_verify ({"path": "<pe>", "trust_ca": "<roots.pem>", "tsa_ca": "<tsa.pem>", "crl": "<crl.pem>"}) reads no default CA store. A part given no material is not_checked, never verified: write "not verified", and report verification, chain, timestamp and revocation separately. unsigned does not exclude catalog signing. Network use is unmeasured: do not call a run offline. Does not show: that a file is benign, or publisher trust.
tools: [authenticode_verify]
requires_host: [osslsigncode]
---

Use when a PE's signing state must be stated, or `authenticode_verify` has answered. Not for judging a publisher, a file's safety or who held a key.

1. **Trust comes only from the call.** `authenticode_verify` runs `osslsigncode verify` (never its own cryptography) against `trust_ca` (the roots the signer's chain must reach), `tsa_ca` (the timestamp authority's roots) and `crl` (a revocation list), all PEM files you supply; `verify_time` sets the time to verify at. It reads no default CA store. Report verification, trust chain, timestamp and revocation separately, each with its policy, trust material and time.
2. **A part given no material is `not_checked`, never `verified`.** With no `trust_ca` a signature is `not_checked` (only the file's digest is compared with the signed one); with no `tsa_ca` a timestamp is reported, with its time, and not verified; with no `crl` revocation is `not_checked`, and OCSP is never consulted. Write "not verified" for each.
3. **`verification`.** `verified` only if every signature is; `failed` if any is (a changed file, a chain that misses the supplied roots, a certificate expired or revoked at the verification time, a timestamp the supplied material does not verify, a damaged certificate table); `unsigned` if the PE declares no certificate table and the program found no signature; otherwise `not_checked`. `unsigned` does not exclude catalog signing: catalog signatures are not read.
4. **Network: unmeasured.** The tool makes no request itself. Whether `osslsigncode` follows a CRL distribution point in a certificate by itself was not measured, so do not describe a run as offline until it has been measured with the network cut.
5. **Only one release is read.** The program's words were checked against osslsigncode 2.5 only; another release is `unsupported`, and an answer whose output was not read whole is `partial` with nothing verified. Record `verifier.version_output`.
6. **A valid signature does not show a file is benign,** and does not show a key was stolen or misused: leave the circumstances open without other evidence (build records, distribution, certificate history). A .NET strong-name signature is not Authenticode and is not read here.

Sensitive output: certificate names are withheld by shape only; another shape is printed.

Shows: what `osslsigncode` accepted against the material you supplied, per signature. Does not show: publisher trust beyond it, safety, intent, or revocation without a `crl`. Record: `verification`, each signature's result, the material and `verify_time` used, `verifier.version_output`, or "signature not verified".
