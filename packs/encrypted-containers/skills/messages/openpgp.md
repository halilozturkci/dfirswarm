---
id: messages/openpgp
title: OpenPGP messages and what their packets show
when: A file or message may be OpenPGP-encrypted.
needs: []
tools: []
requires_host: [gpg]
---

Use only if a file or message may be OpenPGP-encrypted and you read its packets. Not for a private key block found in evidence (`keys/recovery-key-scan`).

An OpenPGP message is a sequence of packets, armoured (`-----BEGIN PGP MESSAGE-----`) or
binary. The packets tell, with no key, how it is protected: a symmetric-key session packet
means a passphrase protects it; public-key session packets each name a recipient key id;
the cipher, a compression packet and an integrity packet are named too.

Read them offline, in a home directory of its own below the job's output, so that no keyring
of the host is touched and nothing is looked up:

    gpg --homedir "$OUT/gnupg" --batch --no-tty --list-packets message.pgp

Make the directory first, mode 0700. Never add an option that fetches or locates a key
(`--recv-keys`, `--locate-keys`, `--auto-key-locate`, `--keyserver`): a key id is an
identifier of a key, and a lookup sends it to a server. Do not add `--decrypt` or
`--show-session-key`: they are for a job that holds a key the case supplied, run with
`secret_output: true`, with the key in a file and not on a command line.

Record the packet types in order, the symmetric or public-key protection, the recipient key
ids as ids (not as people), whether any recipient id is all zeros (a hidden recipient, so
the list of recipients is not the list shown), the cipher and the integrity packet.

**Does not show.** Who a recipient key id belongs to; that a message with hidden recipients
has none; that a key the case holds opens it; what the plaintext is.

**Sensitive output.** `--list-packets` prints key ids and algorithms, never a session key.
Never write a passphrase, a fragment of one or a hash of one.
