---
id: sessions/reconstruct
title: Reconstructing transactions and objects
when: You need what was actually sent, not just who spoke to whom.
needs: [capture/what-you-have]
tools: [pcap_summary, zeek_run]
requires_host: [tcpflow, tcpick, ngrep, tshark, zeek]
---

Use when you need the bytes of a transaction or an object. Not for encrypted payload you hold no secrets for (`metadata/dns-tls`) and not for volume questions (`exfil/volume`).

1. **Sensitive output first.** Any command that can print payload (a follow, `tcpflow`, an object export) runs as a job with `secret_output: true`, outputs and file names under `$OUT`. A finding cites the sealed location, protocol, service and what the credential would grant, never the value or a hash of it.
2. Pick the stream from `pcap_summary` (a tuple row is a lead, not a session) or from `conn.log` (`zeek_run` runs `zeek` for it).
3. **Reassembly is not concatenation.** Use `tcpflow` or `tshark -n -r FILE -q -z follow,tcp,raw,STREAM` (check `tshark -h`) and say which; keep direction, sequence, gaps and retransmissions. Conflicting overlaps mean evasion, corruption or two capture views: intent needs corroboration. Use `tcpick` as a second implementation when overlap decides the answer. `ngrep` is packet triage, not reconstruction.
4. **Encrypted content.** First ask whether the case supplies authorised session key logs. Matching secrets can permit offline decryption of supported TLS and QUIC sessions; a server private key does not open sessions whose key exchange was ephemeral (all of TLS 1.3, RFC 8446). This pack carries no decryption method yet: record the limit. A session you could not read is not evidence that no transaction occurred.
5. Protocol traps: SMB signing is not SMB encryption; FTP has a control and a data channel; a STARTTLS upgrade ends the cleartext; HTTP/2 and HTTP/3 multiplex, so map an object to its stream id, not to the connection.
6. `zeek_run`'s `files.log` lists files its enabled analyzers saw. Its `hashes_produced` and `hash_fields` say whether any hash exists; none is guaranteed, and a hash covers only the bytes Zeek saw. Tie a file to its connection through `conn_uids`.
7. Only if you export protocol objects: `sessions/objects`.

Shows: the bytes one implementation recovered for one stream. Does not show: the same bytes under another implementation, or that the endpoint received them. Record: capture hash, stream and endpoints, time, implementation, object hash (never a credential's).
