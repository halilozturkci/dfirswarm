---
id: sessions/tls-keylogs
title: Authorised TLS decryption from key logs
when: You hold approved TLS secrets and need to know which sessions of a capture they decrypt.
needs: [evidence/captured-secrets]
card: tls_decrypt {"capture": "<capture>", "keylog_file": "<case-supplied key log file>", "out_dir": "<dir under $OUT>"} as a job with secret_output: true: the key log is a FILE input, its text is refused; use_embedded_secrets reads a pcapng's own blocks. Report each flow you rely on by its status and reason (status_counts totals them); a resumed session or a missing ClientHello is no_secret_for_session. Does not show: that a flow without the sign was not decrypted, or who held either end.
tools: [tls_decrypt]
requires_host: [tshark, editcap]
---

Use when the case supplies an authorised key log, or a pcapng that carries its own, and you must say which sessions it opened. Not for choosing what to reconstruct (`sessions/reconstruct`) or for QUIC (`sessions/quic-http3`).

1. **Authority first.** The case authorises the decryption, not the possession of the file. The key log, the decrypted bytes and anything derived from them are sensitive: run `tls_decrypt` as a job with `secret_output: true`, and cite counts, statuses and frames, never a secret or content.
2. **The key log is a FILE reference.** Give `keylog_file` as a job input; text that looks like a key log is refused. `use_embedded_secrets` uses the Decryption Secrets Blocks (DSBs) of a pcapng, and `secrets` says how many there are (`decryption_secrets_blocks`); `key_log_preference` names the tshark preference the file went through. `editcap` can embed a log as DSBs in a copy (check `editcap -h` of the installed build): that copy is as sensitive as the log.
3. **Do the secrets apply?** Check the TLS version, forward secrecy, resumption and whether the handshake is in the capture. TLS 1.2 is matched by `CLIENT_RANDOM` lines, TLS 1.3 by `CLIENT_TRAFFIC_SECRET_0` with `SERVER_TRAFFIC_SECRET_0`; handshake secrets alone open the handshake, not the data. A server private key does not open a forward-secret session. A resumed session, or one whose ClientHello is not captured, is `no_secret_for_session`.
4. **Say which sessions decrypted.** Every flow in `flows` has a `status` (`decrypted`, `partially`, `unsupported`, `no_secret_for_session`, `not_tls`) with a reason, and `status_counts` totals them. Report each session you rely on by its status; name the others as not opened. The sign of decryption is an application protocol tshark names: data in a protocol it cannot dissect shows no sign.
5. **Decrypted is not identified.** What a session carried says nothing about who held either end.
6. **Payload files.** `write_payload` (default true, honoured only in a secret-output job) writes owner-only files under `out_dir`; `payloads` lists stream ids, frame ranges and lengths, and `contains_secret_values` is then true. Open them only in quarantine. A cut or skipped payload makes the answer `partial`.

Shows: which flows the supplied secrets decrypted, by tshark's own sign. Does not show: that a flow without the sign was not decrypted or that the secrets were right for it, who the endpoints were, or traffic that was not captured. Record: capture hash, tshark version, the secrets' source by name and counts (never content), each flow's status, the authority for the decryption.
