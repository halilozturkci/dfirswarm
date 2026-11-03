### Added: four cloud skills for exported evidence, the Entra directory audit, Google Cloud audit logs and Kubernetes audit events

`cloud-forensics` gains four leaves, each opening "Use when ... Not for ..." and naming only fields of the tools that exist (`tests/pack-cloud-skills.test.ts` holds that against `cloud_normalise`):

- **`logs/exported-evidence`** (a prerequisite of `logs/what-exists`, with no needs of its own so the chain stays inside its budget): byte integrity, authenticity and completeness are three claims and none implies another; what to record per file; acquired, parsed, rejected and filtered counts with a locator; the base `check_inputs` and the `cloud-export-inventory` recipe.
- **`entra/directory-audit`**: actor against target, a request against its effect, modified properties as sensitive before and after values, the correlation id, delegated grants against application roles against workload credentials; it agrees with `entra/signins` and `identity/tokens`, which now name `cloud_normalise` where they said the directory audit had no reader.
- **`gcp/audit-logs`**: the four logs (`admin_activity`, `data_access`, `system_event`, `policy_denied`), the delegation chain, event time against receive time, and Data Access settings, sinks, exclusions and retention taken from supplied settings and never from a remembered default.
- **`kubernetes/audit`**: one row is one stage and the stages of an audit id are never separate actions; the audit policy, omitted stages, the backend and a managed service's coverage decide what the file can omit; an API request is not execution; a logged Secret is sensitive; node-local evidence is the Linux pack's, named only if that pack is loaded.

The router names all four, the README says fifteen skills and the doc counts follow. Pack: cloud-forensics.
