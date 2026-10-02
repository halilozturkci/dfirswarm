#!/usr/bin/env python3
"""Lossless original-record archive with a locally held AES-256-GCM key.

No redacted projection is used. Full trace/Pi/tool/log/metadata bytes enter
the archive; original inputs, VM disks, dedicated auth secrets and derived
binary evidence stay private, with the complete source inventory encrypted
inside the archive. Every restored member is checked against its SHA256.
"""
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

source, inventory_file, private, output = map(Path, sys.argv[1:5])
rows = [json.loads(line) for line in inventory_file.read_text().splitlines()]
texts = {'.txt', '.json', '.jsonl', '.md', '.csv', '.tsv', '.log', '.py', '.sh', '.yaml', '.yml', '.xml', '.html', '.js', '.ts'}
auth_files = [Path('/Users/halilozturkci/.pi/agent/auth.json'), Path('/Users/halilozturkci/.codex/auth.json'), Path('/Users/halilozturkci/DFIR/dfirswarm/.pi/agent/auth.json'), source / 'traces/idle-nudge.secrets']
values = set()
def collect(x, name=''):
    if isinstance(x, dict):
        for k, v in x.items(): collect(v, k)
    elif isinstance(x, list):
        for v in x: collect(v, name)
    elif isinstance(x, str) and len(x) >= 16:
        values.add(x)
for f in auth_files:
    if f.is_file():
        try: collect(json.loads(f.read_text()))
        except (ValueError, UnicodeDecodeError): values.update(v for v in f.read_text().splitlines() if len(v) >= 10)
needles = set()
for v in values: needles.update([v.encode(), json.dumps(v)[1:-1].encode(), v.encode('utf-16le')])
overlap = max(map(len, needles), default=1) - 1
selected = []
excluded = {'dedicated_auth_secret': 0, 'derived_binary_or_content_blob': 0}
selected_bytes = 0
for row in rows:
    rel = row['path']
    f = source / rel
    if rel == 'traces/idle-nudge.secrets' or rel.endswith('/agent/auth.json'):
        row['archive_disposition'] = 'private_auth_secret'
        excluded['dedicated_auth_secret'] += 1
        continue
    if rel.startswith('store/blobs/'):
        row['archive_disposition'] = 'private_derived_content_blob'
        excluded['derived_binary_or_content_blob'] += 1
        continue
    with open(f, 'rb') as body: head = body.read(8192)
    if f.suffix.lower() not in texts and b'\0' in head:
        row['archive_disposition'] = 'private_derived_binary'
        excluded['derived_binary_or_content_blob'] += 1
        continue
    row['archive_disposition'] = 'encrypted_full_original'
    selected.append(row)
    selected_bytes += row['bytes']
private.mkdir(parents=True, exist_ok=True)
output.mkdir(parents=True, exist_ok=True)
key, nonce = os.urandom(32), os.urandom(12)
keyfile = private / 'record-archive-key.json'
fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as out: json.dump({'v': 1, 'key_hex': key.hex(), 'algorithm': 'AES-256-GCM'}, out)
encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()

class SplitCipher(io.RawIOBase):
    def __init__(self):
        self.parts, self.part, self.part_size, self.compressed_bytes = [], None, 0, 0
        self.whole_hash, self.part_hash = hashlib.sha256(), None
    def writable(self): return True
    def write_cipher(self, data):
        pos = 0
        while pos < len(data):
            if self.part is None:
                name = f'record.tar.gz.aes.part-{len(self.parts)+1:04d}'
                self.part = open(output / name, 'wb')
                self.part_hash = hashlib.sha256()
                self.part_size = 0
                self.parts.append({'path': name})
            chunk = data[pos:pos + min(len(data)-pos, 16*1024*1024-self.part_size)]
            self.part.write(chunk)
            self.part_hash.update(chunk)
            self.whole_hash.update(chunk)
            self.part_size += len(chunk)
            pos += len(chunk)
            if self.part_size == 16*1024*1024: self.close_part()
    def close_part(self):
        if self.part is None: return
        self.part.close()
        self.parts[-1].update({'bytes': self.part_size, 'sha256': self.part_hash.hexdigest()})
        self.part = None
    def write(self, data):
        self.compressed_bytes += len(data)
        self.write_cipher(encryptor.update(data))
        return len(data)
    def finish(self):
        self.write_cipher(encryptor.finalize())
        self.close_part()

stream = SplitCipher()
scan_bytes = 0
with gzip.GzipFile(fileobj=stream, mode='wb', compresslevel=6, mtime=0, filename='') as compressed:
    with tarfile.open(fileobj=compressed, mode='w|') as tar:
        for n, row in enumerate(selected, 1):
            f = source / row['path']
            h, tail = hashlib.sha256(), b''
            with open(f, 'rb') as body:
                for chunk in iter(lambda: body.read(4*1024*1024), b''):
                    h.update(chunk)
                    scan_bytes += len(chunk)
                    if any(needle in tail + chunk for needle in needles):
                        raise ValueError('auth literal found: archive must remain private; value not emitted')
                    tail = (tail + chunk)[-overlap:] if overlap else b''
            if h.hexdigest() != row['sha256'] or f.stat().st_size != row['bytes']:
                raise ValueError('snapshot source differs from frozen inventory')
            info = tarfile.TarInfo('run/' + row['path'])
            info.size, info.mtime, info.mode = row['bytes'], 0, 0o400
            with open(f, 'rb') as body: tar.addfile(info, body)
            if n % 1000 == 0: print(json.dumps({'archived_records': n, 'total': len(selected)}), flush=True)
        # All private binary/auth exclusions have exact identity/provenance here;
        # the inventory itself can identify secrets, so it is encrypted too.
        inventory = ''.join(json.dumps(row, sort_keys=True, ensure_ascii=False)+'\n' for row in rows).encode()
        info = tarfile.TarInfo('SOURCE-INVENTORY.jsonl')
        info.size, info.mtime, info.mode = len(inventory), 0, 0o400
        tar.addfile(info, io.BytesIO(inventory))
stream.finish()
tag = encryptor.tag
restored = private / 'verified-record.tar.gz'
decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
with open(restored, 'wb') as decoded:
    os.chmod(restored, 0o600)
    for part in stream.parts:
        with open(output / part['path'], 'rb') as encrypted:
            for chunk in iter(lambda: encrypted.read(4*1024*1024), b''): decoded.write(decryptor.update(chunk))
    decoded.write(decryptor.finalize())
expected = {'run/'+row['path']: row for row in selected}
seen, restored_bytes = set(), 0
with tarfile.open(restored, 'r:gz') as tar:
    for member in tar:
        if not member.isfile() or member.name in seen: raise ValueError('invalid/duplicate member')
        h, size = hashlib.sha256(), 0
        with tar.extractfile(member) as body:
            for chunk in iter(lambda: body.read(4*1024*1024), b''):
                h.update(chunk)
                size += len(chunk)
        if member.name == 'SOURCE-INVENTORY.jsonl':
            assert h.hexdigest() == hashlib.sha256(inventory).hexdigest()
        else:
            row = expected[member.name]
            assert h.hexdigest() == row['sha256'] and size == row['bytes']
            restored_bytes += size
        seen.add(member.name)
assert seen == set(expected) | {'SOURCE-INVENTORY.jsonl'}
# An authenticated stream with one modified ciphertext byte must be rejected.
test = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
known = test.update(b'archive integrity control') + test.finalize()
bad = bytearray(known); bad[0] ^= 1
tamper_rejected = False
try:
    check = Cipher(algorithms.AES(key), modes.GCM(nonce, test.tag)).decryptor()
    check.update(bytes(bad)); check.finalize()
except Exception as e:
    from cryptography.exceptions import InvalidTag
    if not isinstance(e, InvalidTag): raise
    tamper_rejected = True
assert tamper_rejected
summary = {'v': 1, 'run': 's421201', 'at': datetime.now(timezone.utc).isoformat(),
    'kind': 'complete original record bytes, lossless gzip then authenticated encryption; not a readable redacted release',
    'algorithm': 'AES-256-GCM', 'nonce_hex': nonce.hex(), 'tag_hex': tag.hex(),
    'key_file_private': str(keyfile), 'parts': stream.parts,
    'ciphertext_sha256': stream.whole_hash.hexdigest(), 'compressed_bytes': stream.compressed_bytes,
    'original_record_files': len(selected), 'original_record_bytes': selected_bytes,
    'all_restored_record_hashes_match': True, 'restored_record_bytes': restored_bytes,
    'encrypted_source_inventory_sha256': hashlib.sha256(inventory).hexdigest(),
    'source_snapshot_files': len(rows), 'private_exclusions': excluded,
    'full_private_snapshot': str(source), 'source_snapshot_originals_truncated': False,
    'tamper_negative_control_rejected': tamper_rejected,
    'auth_scan': {'available_auth_sources': sum(f.is_file() for f in auth_files), 'current_literals': len(values),
                  'forms': len(needles), 'files': len(selected), 'bytes': scan_bytes, 'literal_hits': 0,
                  'values_emitted': False, 'scope': 'current available raw/JSON-escaped/UTF16LE values; not unknown past secrets'},
    'original_inputs_copied': False, 'vm_disks_copied': False,
    'formal_successful_custody': False, 'all14_complete': False, 'flag_verified': False}
(output / 'archive-verification.json').write_text(json.dumps(summary, indent=2)+'\n')
print(json.dumps({k: summary[k] for k in ['original_record_files', 'original_record_bytes', 'compressed_bytes', 'all_restored_record_hashes_match', 'private_exclusions']}), flush=True)
