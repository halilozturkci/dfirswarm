---
id: aws/cloudtrail-integrity
title: CloudTrail integrity, cited from the operator's check
when: A CloudTrail integrity validation is wanted; none can be run here.
needs: []
tools: []
mentions: [aws]
requires_host: []
---

Use when a case asks whether CloudTrail log files are intact and a validation of the digest files is to be cited. Not for reading events (`aws/cloudtrail`), and not for anything you can run: this note routes the check to the operator.

**Boundary.** Offline: no tool of this pack validates a digest file or the chain, the analysis image holds no AWS program and no credential, and you never run one or authenticate to an account. The operator validates outside the image, where the credentials are, and you cite the result they record.

**The operator's step.** `aws cloudtrail validate-logs` with `--trail-arn` (the trail's ARN) and `--start-time` (UTC, ISO 8601); optional `--end-time` (default: now), `--s3-bucket`, `--s3-prefix`, `--account-id` (organization trails) and `--verbose`. It checks the log files delivered between the two times against the trail's digest files. Source: AWS CLI Command Reference, cloudtrail validate-logs, read 2026-11-01, docs.aws.amazon.com/cli/latest/reference/cloudtrail/validate-logs.html. Ask for the command line as run, the trail ARN, both times, the CLI version, who ran it and when, and the output unedited. UNVERIFIED: that page documents only the summary counts, not the wording of a failure, the effect of `--verbose` or the exit status; cite the output in its own words.

**Vocabulary.** Per digest file and per log file: `verified`, `failed` or `unavailable` (not checked, not found or not readable); then the gaps in the chain between digest files. A summary such as "N/M digest files valid" gives N verified; say what became of the other M-N, and never read silence as verified.

**Without the signature.** An export that lost the S3 object metadata (the digest signature) cannot show that validation: record `unavailable`. A file hash shows only that these bytes are the bytes hashed; it is not that validation.

**Shows:** who validated, what, over which times, with which result per class and which gaps. **Does not show:** that the trail recorded every event, that a call took effect, or a person. **Record:** the operator's command and output, or "no validation record supplied: not performed". **Sensitive output:** the trail ARN and account id are identifiers, cited in full; no secret is needed.
