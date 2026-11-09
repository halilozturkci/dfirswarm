#!/usr/bin/env python3
"""Real TLS bytes for the tls_decrypt suite, built independently of the tool.

Two Python `ssl` contexts talk to each other over `ssl.MemoryBIO` (no socket is opened): a TLS 1.2 session and a TLS 1.3 session, each with a handshake and
application data both ways. The client context writes its key log (`keylog_filename`, the NSS format) and every byte each side sends is recorded, in order,
with its direction. The records are cut into TCP segments by the test (tests/pack-network-tls-decrypt.test.ts), which also writes the pcap and pcapng files.

Usage: network-tls-fixture.py OUT.json
Needs the `openssl` command to make a throwaway self-signed certificate; exit status 3 and no output file when it is not there.
What is written: {"sessions": [{"name", "version", "client_random", "chunks": [{"dir": "c"|"s", "hex", "records": [[content type, handshake type or 0], ...]}],
"client_plaintext", "server_plaintext", "keylog_lines": ["LABEL random secret", ...]}]}
"""
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile


def certificate(directory):
    key, crt = os.path.join(directory, "key.pem"), os.path.join(directory, "cert.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", crt, "-days", "2",
                    "-subj", "/CN=example.test"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return crt, key


def parse_records(blob):
    """The (content type, handshake type) of each TLS record in a chunk: from the 5-byte record headers, the handshake type being the first byte of a handshake record."""
    out, at = [], 0
    while at + 5 <= len(blob):
        kind, length = blob[at], int.from_bytes(blob[at + 3:at + 5], "big")
        out.append([kind, blob[at + 5] if kind == 22 and at + 5 < len(blob) else 0])
        at += 5 + length
    return out


def run_session(name, version, crt, key, directory):
    keylog = os.path.join(directory, name + ".keylog")
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(crt, key)
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE
    client.keylog_filename = keylog
    for ctx in (server, client):
        ctx.minimum_version = ctx.maximum_version = version
    cin, cout, sin, sout = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    c = client.wrap_bio(cin, cout, server_hostname="example.test")
    s = server.wrap_bio(sin, sout, server_side=True)
    chunks = []

    def pump():
        moved = False
        for direction, out_bio, in_bio in (("c", cout, sin), ("s", sout, cin)):
            data = out_bio.read()
            if data:
                chunks.append({"dir": direction, "hex": data.hex(), "records": parse_records(data)})
                in_bio.write(data)
                moved = True
        return moved

    for _ in range(50):
        for end in (c, s):
            try:
                end.do_handshake()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
        if not pump():
            break
        try:
            c.do_handshake()
            s.do_handshake()
            pump()
            break
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            continue
    request = b"GET /account/export?id=7 HTTP/1.1\r\nHost: example.test\r\nCookie: sid=fixture-session-value\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 27\r\nContent-Type: text/plain\r\n\r\nthe decrypted fixture body."
    c.write(request)
    pump()
    s.read(len(request))
    s.write(response)
    pump()
    c.read(len(response))
    first = bytes.fromhex(chunks[0]["hex"])
    random = first[11:43].hex()            # record header 5 + handshake header 4 + client version 2
    with open(keylog, encoding="ascii") as fh:
        lines = [line.strip() for line in fh if line.strip()]
    # the client's own bytes are the plaintext the client sent; a TLS 1.3 server also sends session tickets after the handshake (not counted as plaintext here)
    return {"name": name, "version": {ssl.TLSVersion.TLSv1_2: "1.2", ssl.TLSVersion.TLSv1_3: "1.3"}[version], "client_random": random, "chunks": chunks,
            "client_plaintext": request.hex(), "server_plaintext": response.hex(), "keylog_lines": lines}


def main():
    if shutil.which("openssl") is None:
        sys.exit(3)
    with tempfile.TemporaryDirectory() as directory:
        crt, key = certificate(directory)
        sessions = [run_session("tls12", ssl.TLSVersion.TLSv1_2, crt, key, directory), run_session("tls13", ssl.TLSVersion.TLSv1_3, crt, key, directory)]
    with open(sys.argv[1], "w", encoding="ascii") as fh:
        json.dump({"sessions": sessions}, fh)


if __name__ == "__main__":
    main()
