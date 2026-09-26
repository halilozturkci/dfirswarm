import sys, json, hashlib, os, struct
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[0]).resolve().parents[1]))
from _output import LosslessPage

# Read input
inp = json.load(sys.stdin)
path = inp.get("path", "")
sig_name = inp.get("sig", "")  # specific sig or "all"
context = inp.get("context", 64)
max_hits = inp.get("max_hits", 500)

# File signatures: name -> (header_hex, footer_hex_or_none, min_size, max_size)
SIGS = {
    "MZ":    ("4D5A", None, 64, 50*1024*1024),     # PE/DOS executable
    "PK":    ("504B0304", None, 32, 200*1024*1024), # ZIP/DOCX/XLSX
    "regf":  ("72656766", None, 4096, 200*1024*1024), # Registry hive
    "MAM":   ("4D414D", None, 1024, 50*1024*1024),  # MAM prefetch
    "SCCA":  ("53434341", None, 1024, 50*1024*1024), # SCCA prefetch
    "EVTX":  ("456C6646696C6500", None, 4096, 200*1024*1024), # EVTX event log
    "OLE":   ("D0CF11E0A1B11AE1", None, 512, 100*1024*1024),  # OLE2/Office
    "LNK":   ("4C0000000114020000000000C000000000000046", None, 512, 64*1024), # LNK
    "SQLite":("53514C69746520666F726D6174203300", None, 512, 100*1024*1024), # SQLite
    "RAR":   ("526172211A0700", None, 32, 100*1024*1024),  # RAR
    "7z":    ("377ABCAF271C", None, 32, 100*1024*1024),    # 7-zip
    "GZ":    ("1F8B08", None, 32, 100*1024*1024),          # gzip
    "BZ2":   ("425A68", None, 32, 100*1024*1024),          # bzip2
    "PDF":   ("255044462D", None, 64, 50*1024*1024),       # PDF
    "PNG":   ("89504E470D0A1A0A", None, 64, 50*1024*1024), # PNG
    "JFIF":  ("FFD8FFE0", "FFD9", 64, 20*1024*1024),       # JPEG
    "PCH":   ("4D414D04", None, 1024, 50*1024*1024),       # MAM v2 prefetch
}

def hex_to_bytes(h):
    return bytes.fromhex(h)

def scan_file(filepath, sig_defs, context, max_hits):
    results = {}
    file_size = os.path.getsize(filepath)
    
    # Read the file in chunks to find signatures
    # For efficiency, read whole file in streaming mode
    CHUNK = 64 * 1024 * 1024  # 64MB chunks
    
    with open(filepath, 'rb') as f:
        for name, (header_hex, footer_hex, minsize, maxsize) in sig_defs.items():
            header = hex_to_bytes(header_hex)
            hits = LosslessPage("sig_carve-" + name, [filepath, name], max_hits)
            
            f.seek(0)
            offset = 0
            overlap = len(header) - 1
            buf = b''
            
            while offset < file_size:
                f.seek(offset)
                chunk = f.read(CHUNK + overlap)
                if not chunk:
                    break
                
                buf = buf[-overlap:] + chunk if buf else chunk
                
                pos = 0
                while True:
                    idx = buf.find(header, pos)
                    if idx == -1:
                        break
                    abs_offset = offset + idx - (overlap if offset > 0 else 0)
                    if abs_offset >= 0:
                        # Get context bytes
                        f.seek(max(0, abs_offset - 16))
                        ctx = f.read(context + 16 + len(header))
                        ctx_start = min(16, abs_offset)
                        ctx_snippet = ctx[ctx_start:ctx_start + context]
                        
                        hits.add({
                            "offset": abs_offset,
                            "hex_preview": ctx_snippet[:32].hex(' '),
                            "ascii_preview": ''.join(chr(b) if 32<=b<127 else '.' for b in ctx_snippet[:64])
                        })
                    pos = idx + 1
                
                offset += CHUNK
            page = hits.finish()
            results[name] = {
                "count": page["matched"],
                "hits": hits.page,
                **page,
            }
    
    return results

if sig_name and sig_name != "all":
    sigs_to_scan = {sig_name: SIGS[sig_name]} if sig_name in SIGS else {}
else:
    sigs_to_scan = SIGS

results = scan_file(path, sigs_to_scan, context, max_hits)
print(json.dumps(results, indent=2))
