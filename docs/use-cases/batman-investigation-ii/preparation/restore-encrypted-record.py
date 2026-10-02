#!/usr/bin/env python3
"""Restore the exact recorded bytes into a fresh private directory.

Usage: restore-encrypted-record.py ARCHIVE_DIRECTORY OUTPUT_DIRECTORY [KEY_FILE]
No record content or key is printed and no archived program is executed.
"""
import hashlib
import json
import os
import sys
import tarfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

archive, destination = map(Path, sys.argv[1:3])
manifest = json.loads((archive / 'archive-verification.json').read_text())
keyfile = Path(sys.argv[3]) if len(sys.argv) > 3 else Path(manifest['key_file_private'])
key = bytes.fromhex(json.loads(keyfile.read_text())['key_hex'])
if len(key) != 32: raise ValueError('invalid archive key')
destination.mkdir(mode=0o700, parents=True, exist_ok=False)
compressed = destination / '.authenticated-record.tar.gz'
dec = Cipher(algorithms.AES(key), modes.GCM(bytes.fromhex(manifest['nonce_hex']), bytes.fromhex(manifest['tag_hex']))).decryptor()
whole = hashlib.sha256()
with open(compressed, 'wb') as output:
    os.chmod(compressed, 0o600)
    for part in manifest['parts']:
        rel = Path(part['path'])
        if rel.is_absolute() or '..' in rel.parts: raise ValueError('invalid part path')
        h, count = hashlib.sha256(), 0
        with open(archive / rel, 'rb') as body:
            for chunk in iter(lambda: body.read(4*1024*1024), b''):
                h.update(chunk); whole.update(chunk); count += len(chunk)
                output.write(dec.update(chunk))
        if h.hexdigest() != part['sha256'] or count != part['bytes']: raise ValueError('archive part differs')
    output.write(dec.finalize())  # Authenticate before opening/extracting tar.
if whole.hexdigest() != manifest['ciphertext_sha256']: raise ValueError('whole ciphertext differs')
with tarfile.open(compressed, 'r:gz') as tar:
    body = tar.extractfile('SOURCE-INVENTORY.jsonl').read()
    if hashlib.sha256(body).hexdigest() != manifest['encrypted_source_inventory_sha256']: raise ValueError('inventory differs')
    rows = [json.loads(line) for line in body.decode().splitlines()]
    expected = {'run/'+row['path']: row for row in rows if row['archive_disposition'] == 'encrypted_full_original'}
    seen = set()
    for member in tar:
        p = Path(member.name)
        if not member.isfile() or p.is_absolute() or '..' in p.parts or member.name in seen:
            raise ValueError('invalid archive member')
        if member.name != 'SOURCE-INVENTORY.jsonl' and member.name not in expected:
            raise ValueError('unexpected archive member')
        target = destination / p
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        h, count = hashlib.sha256(), 0
        with tar.extractfile(member) as src, open(target, 'xb') as output:
            os.chmod(target, 0o600)
            for chunk in iter(lambda: src.read(4*1024*1024), b''):
                output.write(chunk); h.update(chunk); count += len(chunk)
        if member.name in expected:
            row = expected[member.name]
            if h.hexdigest() != row['sha256'] or count != row['bytes']: raise ValueError('restored record differs')
        seen.add(member.name)
if seen != set(expected) | {'SOURCE-INVENTORY.jsonl'}: raise ValueError('restored file inventory differs')
compressed.unlink()
print(json.dumps({'restored_original_records': len(expected), 'all_member_hashes_match': True, 'destination': str(destination)}))
