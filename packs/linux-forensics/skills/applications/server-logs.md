---
id: applications/server-logs
title: Web, proxy, application and database logs
when: Reading web, proxy, application or database server logs from the configuration that wrote them.
needs: []
card: linux_triage {"source": "<image or root>", "out_dir": "work/<your id>/<name>", "groups": ["web"]} covers only web servers dissect.target knows: read proxy, application and database logs from the raw files; empty is not absence. Read the server's log format and rotation before a line. A status is the server's answer, not the outcome; behind a proxy the client address is the proxy, and forwarded headers count only from a trusted hop. Does not show: who sent a request, or that an attack succeeded.
tools: [linux_triage]
requires_host: []
---

Use when a server on the host kept access, error, application or database logs that matter to the case. Not for authentication lines (`logs/auth`) or the audit log (`logs/auditd`).

Read the configuration before the log: which server and version wrote it, the log format directive (a `LogFormat`, `log_format` or the proxy's own), the log paths and rotation (`logrotate` settings, compressed and numbered files), which virtual hosts or locations log where, and whether logging was off or sent elsewhere (a syslog socket, a remote collector, the journal). A line cannot be read without its format, and a log under another name or place is not found by a name search.

Keep four things apart: a request (what a client sent, as the server saw it), a response (what the server returned: a status is the server's answer, not the application's outcome), an application action (what the code did, in the application's own log) and a host command (what a process ran, which is in the audit log and histories, not here). A 200 on an upload does not show a file stored, and a request in an access log does not show who sent it. The client address is the socket's peer, so behind a proxy it is the proxy: forwarded-address headers (`X-Forwarded-For`, `Forwarded`) are client-supplied unless the proxy overwrote them, so trust one only from the hop the configuration shows is trusted (`real_ip_header`, `set_real_ip_from`, `RemoteIPHeader`), and say which hop each address is. Times carry the server's zone and its log format's resolution; the time logged is often when the request finished.

`linux_triage` has a `web` family (dissect.target's `webserver.logs`) for the web servers dissect.target knows; it does not cover a proxy, an application or a database log, or a server it does not recognise, so read those from the raw files. If the network pack is loaded, its `logs/web-proxy-firewall` note covers proxy and firewall logs. Transaction-log examination (database write-ahead and binary logs) is not provided: a database's own query or slow-query log is read as an application log, and its redo or binary logs are not examined by this pack.

Shows: requests, responses and errors as the server logged them. Does not show: who sent a request, that an attack succeeded, or what a database changed. Record: the server and version, the configuration read, each log's path, rotation and time range, the format directive, and what was off or missing.

Sensitive output: URLs, headers and query strings can hold tokens and passwords. Keep `linux_triage` in a `secret_output` job when you read them; cite file and line, never a value or a hash of it.
