#!/usr/bin/env bash
set -euo pipefail
PACK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/network-pack.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

python3 -m py_compile "$PACK"/tools/*/run.py "$PACK"/recipes/*/run.py
jq -e '.binaries | map(.name) | index("tcpdump") and index("tcpick") and index("ngrep") and index("capinfos")' \
  "$PACK/requires/host.json" >/dev/null || fail "examiner capture programs are not declared"
pass "network pack Python compiles and examiner programs are declared"

python3 - "$TMP" <<'PY'
import json, os, struct, sys
d = sys.argv[1]
eth = bytes.fromhex("00112233445566778899aabb0800")
ip = bytes.fromhex("4500002800014000400600000a0000010a000002")
tcp = struct.pack("!HHIIHHHH", 12345, 443, 1, 0, (5 << 12) | 2, 1024, 0, 0)
packet = eth + ip + tcp
with open(os.path.join(d, "one.pcap"), "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    f.write(struct.pack("<IIII", 1700000000, 500000, len(packet), len(packet)) + packet)
with open(os.path.join(d, "one.pcap"), "rb") as source, open(os.path.join(d, "truncated.pcap"), "wb") as target:
    target.write(source.read()[:-5])
same_ip = bytes.fromhex("4500002800014000400600007f0000017f000001")
request = eth + same_ip + struct.pack("!HHIIHHHH", 50000, 80, 1, 0, (5 << 12) | 2, 1024, 0, 0)
response = eth + same_ip + struct.pack("!HHIIHHHH", 80, 50000, 1, 2, (5 << 12) | 0x12, 1024, 0, 0)
with open(os.path.join(d, "same-ip.pcap"), "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for second, frame in enumerate((request, response)):
        f.write(struct.pack("<IIII", 1700000000 + second, 0, len(frame), len(frame)) + frame)

def block(end, kind, body):
    total = 12 + len(body)
    return struct.pack(end + "II", kind, total) + body + struct.pack(end + "I", total)
def pcapng(path, end, magic):
    shb_body = magic + struct.pack(end + "HHq", 1, 0, -1)
    # if_tsresol = 10^-9 and if_tsoffset = +2 seconds
    opts = struct.pack(end + "HH", 9, 1) + b"\x09\0\0\0" + struct.pack(end + "HHq", 14, 8, 2) + struct.pack(end + "HH", 0, 0)
    idb = struct.pack(end + "HHI", 1, 0, 65535) + opts
    ticks = 1700000000 * 1_000_000_000 + 500_000_000
    padded = packet + b"\0" * ((-len(packet)) % 4)
    epb = struct.pack(end + "IIIII", 0, ticks >> 32, ticks & 0xffffffff, len(packet), len(packet)) + padded
    with open(path, "wb") as f:
        f.write(block(end, 0x0A0D0D0A, shb_body))
        f.write(block(end, 1, idb))
        f.write(block(end, 6, epb))
pcapng(os.path.join(d, "little.pcapng"), "<", b"\x4d\x3c\x2b\x1a")
pcapng(os.path.join(d, "big.pcapng"), ">", b"\x1a\x2b\x3c\x4d")
with open(os.path.join(d, "simple-truncated.pcapng"), "wb") as f:
    f.write(block("<", 0x0A0D0D0A, b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1)))
    f.write(block("<", 1, struct.pack("<HHI", 1, 0, 53)))
    spb_data = packet[:53] + b"\0" * 3
    f.write(block("<", 3, struct.pack("<I", len(packet)) + spb_data))

open(os.path.join(d, "logs.txt"), "w").write(
    '192.0.2.1 - - [14/Nov/2023:22:13:20 +0000] "GET /a HTTP/1.1" 200 12 "-" "ua"\n'
    '1700000000.1 30 192.0.2.2 TCP_MISS/200 321 GET http://example.test/a alice DIRECT/203.0.113.80 text/html\n'
    'Nov 14 fw DROP IN=eth0 OUT=eth1 SRC=192.0.2.3 DST=203.0.113.8 NAT_SRC=198.51.100.7 NAT_DST=10.0.0.8 LEN=60 PROTO=TCP SPT=51515 DPT=443 SYN ACK\n'
    'not parsed\n')
PY

summary="$PACK/tools/pcap_summary/run.py"
for capture in one.pcap little.pcapng big.pcapng; do
  out="$(printf '{"path":"%s/%s","with_starts":true}' "$TMP" "$capture" | python3 "$summary")"
  jq -e '.packets == 1 and .conversation_count == 1 and .conversations[0].connection_starts == 1' <<<"$out" >/dev/null \
    || fail "$capture was not parsed as one TCP SYN: $out"
done
little="$(printf '{"path":"%s/little.pcapng"}' "$TMP" | python3 "$summary")"
jq -e '.first_packet == "2023-11-14T22:13:22.500000Z"' <<<"$little" >/dev/null \
  || fail "pcapng time resolution and offset were not applied: $little"
if printf '{"path":"%s/one.pcap","top":1}' "$TMP" | python3 "$summary" >/dev/null 2>&1; then
  : # one conversation, so nothing was omitted
fi
if printf '{"path":"%s/one.pcap","max_packets":1}' "$TMP" | python3 "$summary" >/dev/null 2>&1; then
  fail "max_packets must not silently truncate a forensic summary"
fi
if printf '{"path":"%s/truncated.pcap"}' "$TMP" | python3 "$summary" >/dev/null 2>&1; then
  fail "truncated packet bodies must make pcap_summary fail"
fi
same_ip="$(printf '{"path":"%s/same-ip.pcap"}' "$TMP" | python3 "$summary")"
jq -e '.conversation_count == 1 and .conversations[0].a_to_b_bytes == 54 and .conversations[0].b_to_a_bytes == 54' <<<"$same_ip" >/dev/null \
  || fail "same-IP session direction was not distinguished by port: $same_ip"
same_ip_endpoint="$(printf '{"path":"%s/same-ip.pcap","group":"endpoint"}' "$TMP" | python3 "$summary")"
jq -e '.conversation_count == 1 and .conversations[0].a_to_b_bytes == 54 and .conversations[0].b_to_a_bytes == 54' <<<"$same_ip_endpoint" >/dev/null \
  || fail "same-IP endpoint-group direction was not distinguished by port: $same_ip_endpoint"
simple="$(printf '{"path":"%s/simple-truncated.pcapng"}' "$TMP" | python3 "$summary")"
jq -e '.packets == 1 and (.notes | any(test("captured shorter")))' <<<"$simple" >/dev/null \
  || fail "Simple Packet Block snap-length truncation/padding was not accounted for: $simple"
pass "classic, little-endian and big-endian pcapng parse completely with nanosecond time resolution"

printf '{"path":"%s/logs.txt","out_dir":"%s/log-out"}' "$TMP" "$TMP" | \
  python3 "$PACK/tools/network_log_summary/run.py" > "$TMP/log-result.json"
jq -e '.lines == 4 and .parsed == 3 and .unparsed == 1' "$TMP/log-result.json" >/dev/null \
  || fail "network logs were not accounted for: $(cat "$TMP/log-result.json")"
[[ "$(wc -l < "$TMP/log-out/normalized.tsv" | tr -d ' ')" -eq 4 ]] || fail "normalised TSV lost a parsed line"
[[ "$(wc -l < "$TMP/log-out/unparsed.tsv" | tr -d ' ')" -eq 2 ]] || fail "unparsed TSV lost an unparsed line"
grep -q $'alice\t\t30\tDIRECT/203.0.113.80\ttext/html' "$TMP/log-out/normalized.tsv" \
  || fail "Squid user, elapsed time, hierarchy and MIME were not retained"
grep -q $'eth0\teth1\t198.51.100.7\t10.0.0.8\tSYN,ACK' "$TMP/log-out/normalized.tsv" \
  || fail "firewall interfaces, NAT fields and TCP flags were not retained"
pass "web, Squid and firewall logs normalise and every source line is accounted for"

mkdir "$TMP/fake-bin"
cat >"$TMP/fake-bin/tshark" <<'SH'
#!/bin/sh
awk 'BEGIN { for (i = 0; i < 4096; i++) printf "T" > "/dev/stderr" }'
exit 7
SH
cat >"$TMP/fake-bin/suricata" <<'SH'
#!/bin/sh
awk 'BEGIN { for (i = 0; i < 5000; i++) printf "S" > "/dev/stderr" }'
exit 8
SH
cat >"$TMP/fake-bin/zeek" <<'SH'
#!/bin/sh
printf '%s\n' '#separator \x09' '#fields\tts\tuid' '#types\ttime\tstring' '1.0\tC1' >conn.log
awk 'BEGIN { for (i = 0; i < 3000; i++) printf "Z" }'
awk 'BEGIN { for (i = 0; i < 3500; i++) printf "E" > "/dev/stderr" }'
exit 9
SH
chmod +x "$TMP/fake-bin/tshark" "$TMP/fake-bin/suricata" "$TMP/fake-bin/zeek"
mkdir "$TMP/export-fail"
if printf '{"path":"%s/one.pcap","out_dir":"%s/export-fail","protocols":["http"]}' "$TMP" "$TMP" | \
  PATH="$TMP/fake-bin:$PATH" python3 "$PACK/tools/pcap_extract/run.py" >"$TMP/export-fail.json"; then
  fail "pcap_extract reported a failed tshark analysis as success"
fi
jq -e '.ok == false and .errors[0].exit_code == 7 and .errors[0].stderr' "$TMP/export-fail.json" >/dev/null \
  || fail "pcap_extract did not name the failed analysis and its complete diagnostic"
[[ "$(wc -c < "$TMP/export-fail/_logs/http.stderr" | tr -d ' ')" -eq 4096 ]] \
  || fail "pcap_extract truncated tshark stderr"
printf '%s\n' 'alert tcp any any -> any any (msg:"test"; sid:1; rev:1;)' >"$TMP/test.rules"
mkdir "$TMP/suricata-fail"
if printf '{"path":"%s/one.pcap","rules":"%s/test.rules","out_dir":"%s/suricata-fail"}' "$TMP" "$TMP" "$TMP" | \
  PATH="$TMP/fake-bin:$PATH" python3 "$PACK/tools/suricata_run/run.py" >"$TMP/suricata-fail.json"; then
  fail "suricata_run reported a failed Suricata analysis as success"
fi
jq -e '.exit_code == 8 and .stderr and .stdout' "$TMP/suricata-fail.json" >/dev/null \
  || fail "suricata_run did not name the failed analysis and its complete diagnostic"
[[ "$(wc -c < "$TMP/suricata-fail/suricata.stderr" | tr -d ' ')" -eq 5000 ]] \
  || fail "suricata_run truncated Suricata stderr"
mkdir "$TMP/zeek-fail"
if printf '{"path":"%s/one.pcap","out_dir":"%s/zeek-fail"}' "$TMP" "$TMP" | \
  PATH="$TMP/fake-bin:$PATH" python3 "$PACK/tools/zeek_run/run.py" >"$TMP/zeek-fail.json"; then
  fail "zeek_run reported a failed Zeek analysis as success"
fi
jq -e '.ok == false and .exit_code == 9 and .stderr and .stdout and .logs.conn.total == 1' "$TMP/zeek-fail.json" >/dev/null \
  || fail "zeek_run did not preserve its logs and name the failed analysis diagnostics"
[[ "$(wc -c < "$TMP/zeek-fail/zeek.stdout" | tr -d ' ')" -eq 3000 ]] \
  || fail "zeek_run truncated Zeek stdout"
[[ "$(wc -c < "$TMP/zeek-fail/zeek.stderr" | tr -d ' ')" -eq 3500 ]] \
  || fail "zeek_run truncated Zeek stderr"
pass "failed tshark, Suricata and Zeek analyses fail closed and retain complete diagnostics"

target="$(printf '{"paths":["%s/one.pcap"],"name":"inputs/one.pcap"}' "$TMP")"
python3 "$PACK/recipes/network-capture/run.py" detect --target "$target" | jq -e '.applies' >/dev/null \
  || fail "capture recipe did not detect classic pcap"
if command -v tshark >/dev/null && command -v capinfos >/dev/null; then
  python3 "$PACK/recipes/network-capture/run.py" run --target "$target" --out "$TMP/catalog" >/dev/null \
    || fail "capture recipe failed: $(cat "$TMP/catalog/coverage.json")"
  jq -e '.status == "complete"' "$TMP/catalog/coverage.json" >/dev/null || fail "capture recipe was incomplete"
  [[ -s "$TMP/catalog/packets.tsv" && -s "$TMP/catalog/index.tsv" ]] || fail "capture recipe listings are missing"
  pass "capture recipe detects and inventories a pcap"
else
  echo "skip - tshark/capinfos not on this host; rebuilt-image proof is required"
fi
