---
id: kubernetes/audit
title: Kubernetes audit events and stages
when: Supplied API audit events must say which user did what to which object.
needs: [logs/what-exists]
card: cloud_normalise {"path": "<audit events>", "provider": "kubernetes"}: read status first; tenant is empty, so record which cluster and backend the file came from. One row is one stage: rows sharing event_id (the audit id) are one request, not several actions; RequestReceived has outcome unknown. principal is the requester, impersonated_principal who it ran as; source_ip lists the client, then proxies. The audit policy and backend decide what was logged: an absent request shows nothing. An API request to create or exec is not execution on a node. Secret bodies are withheld whole. Does not show: a person, that a request took effect or that anything ran.
tools: [cloud_normalise]
requires_host: []
---

Use when you hold Kubernetes API audit events and must say who asked the API server for what, from where, and what it answered. Not for what ran on a node (see below) or for a cloud provider's own audit log. Offline: supplied exports only; never connect to the cluster.

**Read the coverage `cloud_normalise` returns first.** `status` is complete only if every event was read and became a row. The event names no cluster: `tenant` is empty, so record which cluster and which audit backend the file came from before you cite it.

**One row is one stage.** `event_id` is the audit id and `stage` is `RequestReceived`, `ResponseStarted`, `ResponseComplete` or `Panic`: the stages of one request are separate rows, never separate actions. Only a stage that carries a response has an `outcome`; `RequestReceived` is `unknown`.

**Fields that carry the case:** `action` (the verb), `request_uri`, `resource` (namespace, resource, subresource, name), `object_ref`, `level`, `principal` (the user name) with `groups` and `user_extra`, `impersonated_principal` (the user the request ran as), `source_ip` (a list: the client, then proxies), `user_agent`, `outcome_detail` (response status and the authorization decision) and `annotations`.

**What the file can omit.** The audit policy decides which requests are logged, at which level, and which stages are omitted; the backend decides delivery; a managed service logs what its operator chose. A request absent from the file shows none of these. Take them from the supplied policy and backend settings.

**A request is not execution.** An API call to create, exec or delete is a request to the API server; what ran inside a container or on a node is node-local evidence, in the Linux pack if it is loaded (check the run's skill index for its container notes).

**A logged Secret is sensitive.** A request or response body that is a Secret object is replaced whole by a marker, and its original is written only with `write_values`; the other bodies go through the credential rules.

**Does not show:** a person; that a request took effect; that anything ran; what the policy did not log; a complete export.

**Sensitive output:** run the tool as a job with `secret_output: true`; it withholds credential-named and credential-shaped values and Secret bodies. Other secrets are not recognised.
