import json, subprocess, sys, os, shlex, urllib.parse, math, collections
obj=json.load(sys.stdin)
missing=[k for k in ('db_path','sql') if not isinstance(obj.get(k), str) or not obj.get(k)]
if missing:
    print(json.dumps({'ok': False, 'error': 'need ' + ' and '.join(missing), 'params': ['db_path', 'sql', 'csv', 'readonly']}))
    raise SystemExit(1)
db=obj['db_path']
sql=obj['sql']
csv=bool(obj.get('csv', False))
readonly=bool(obj.get('readonly', True))
if not os.path.exists(db):
    print(json.dumps({'ok': False, 'error': 'database not found', 'db_path': db}))
    raise SystemExit(1)
# sqlite3 says only "file is not a database" for anything else, and the
# sixth CTF round's agents met it on Element's SQLCipher events.db without
# learning why. The first page says it: a SQLite file starts with its magic,
# an encrypted one (SQLCipher, or an app's own) is random from byte 0, and
# another format has a header of its own.
if os.path.isfile(db) and os.path.getsize(db) > 0:
    with open(db, 'rb') as fh:
        page = fh.read(4096)
    if not page.startswith(b'SQLite format 3\x00'):
        counts = collections.Counter(page)
        entropy = -sum(c / len(page) * math.log2(c / len(page)) for c in counts.values())
        print(json.dumps({
            'ok': False,
            'error': 'not a SQLite file: its first bytes are not the SQLite magic',
            'db_path': db,
            'header_hex': page[:16].hex(),
            'first_page_entropy_bits_per_byte': round(entropy, 3),
            'reading': ('random from the first byte: an encrypted database (SQLCipher or an app\'s own); '
                        'no query runs without its key' if entropy > 7.5 else
                        'another format: identify it from its header (file_type)'),
        }))
        raise SystemExit(1)
# Use immutable URI for read-only safety when requested. The sqlite3 shell
# reads a file: name as a URI by itself; it has no -uri option (every call
# with readonly=true failed on "unknown option: -uri"). immutable=1 also opens
# a WAL database on a read-only mount, where plain mode=ro cannot create -shm.
# The path is percent-encoded: a "#" or "?" in it would end the name early.
if readonly:
    db_arg=f'file:{urllib.parse.quote(db)}?mode=ro&immutable=1'
else:
    db_arg=db
cmd=['sqlite3']
# -csv before -header: a newer shell (3.54) resets the header switch when
# -csv sets the mode, and "-header -csv" printed the rows without one.
if csv:
    cmd += ['-csv','-header']
cmd += [db_arg, sql]
# A text column can hold bytes that are not UTF-8 (an ActivitiesCache
# Payload was, on the sixth CTF round, and the tool died decoding it):
# they come back as \\xNN escapes, every byte still said.
proc=subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='backslashreplace')
print(json.dumps({'ok': proc.returncode==0, 'returncode': proc.returncode, 'stdout': proc.stdout, 'stderr': proc.stderr}))
if proc.returncode != 0:
    raise SystemExit(proc.returncode)
