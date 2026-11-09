### Added: network-forensics: two session skills, authorised TLS decryption from key logs and QUIC with HTTP/3

- **`sessions/tls-keylogs`** covers whether supplied secrets apply (the TLS version, forward secrecy, resumption, a missing handshake; `CLIENT_RANDOM` for TLS 1.2, the traffic secrets for TLS 1.3), the key log as a FILE reference (`keylog_file`, never its text), the Decryption Secrets Blocks of a pcapng, which sessions decrypted (the `status` of each flow of `tls_decrypt`), the sensitivity of everything derived, and that decryption is not endpoint identity.
- **`sessions/quic-http3`** covers the tshark build and the fields of `quic_inspect`, handshake metadata of an Initial against decryption, the datagram and packet rows and their `limits`, connection ids, migration, Retry and Version Negotiation, HTTP/3 stream ids, and that a UDP tuple is not a session. It says this pack shows nothing about what Zeek or Suricata write for QUIC.
- **`metadata/dns-tls`** points to the QUIC leaf (the paragraph already names `quic_inspect`); `network/router` names both leaves; the README and the counts say 19 skills.
- Pack raised: `network-forensics` (minor).
- Tests: `tests/pack-network-skills.test.ts`: the new leaves, the fields they name against the two tools' scripts, the key log as a file in both, and the pointer.
