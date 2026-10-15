#!/usr/bin/env bash
# The virtualization pack's own suite: the tools compile, and each reads one small synthetic input written here from the
# formats' public descriptions. The full suites are tests/pack-virtualization-*.test.ts in the repository.
set -euo pipefail
PACK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/virt-pack.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

python3 -m py_compile "$PACK"/tools/*/run.py
pass "virtualization pack Python compiles"

mkdir -p "$TMP/inputs/vm" "$TMP/work/s1"
cat > "$TMP/inputs/vm/base.vmdk" <<'EOF'
# Disk DescriptorFile
version=1
CID=aabbccdd
parentCID=ffffffff
createType="monolithicFlat"

# Extent description
RW 8 FLAT "base-flat.vmdk" 0
EOF
head -c 4096 /dev/zero > "$TMP/inputs/vm/base-flat.vmdk"
cat > "$TMP/inputs/vm/child.vmdk" <<'EOF'
# Disk DescriptorFile
version=1
CID=11223344
parentCID=aabbccdd
createType="vmfsSparse"
parentFileNameHint="base.vmdk"

# Extent description
RW 8 FLAT "child-flat.vmdk" 0
EOF
head -c 4096 /dev/zero > "$TMP/inputs/vm/child-flat.vmdk"
printf 'displayName = "web01"\nscsi0:0.fileName = "child.vmdk"\n' > "$TMP/inputs/vm/web.vmx"
printf 'UPID:pve1:00000B73:0000D2C5:65A3F1B0:qmdelsnapshot:100:root@pam: 65A3F1B2 OK\n' > "$TMP/inputs/index"

run() { (cd "$TMP" && AGENT_ID=s1 python3 "$PACK/tools/$1/run.py"); }

out="$(echo '{"root":"inputs/vm"}' | run snapshot_chain_check)"
jq -e '.status == "complete" and .chain_summary.complete == 1 and (.edges | length) == 1 and .edges[0].id_check == "match"' <<<"$out" >/dev/null \
  || fail "snapshot_chain_check did not find one complete chain: $out"
pass "snapshot_chain_check reads a two-disk VMDK chain and matches the parent CID"

out="$(echo '{"root":"inputs/vm"}' | run virtualization_inventory)"
jq -e '.counts.vms == 1 and .counts.disks == 1 and .vms[0].name == "web01" and .disks[0].in_set == "yes"' <<<"$out" >/dev/null \
  || fail "virtualization_inventory did not list the VM and its disk: $out"
pass "virtualization_inventory lists a VMware VM and finds its disk among the files"

out="$(echo '{"path":"inputs/index"}' | run backup_audit_normalise)"
jq -e '.counts.events == 1 and .events[0].category == "snapshot_delete" and .events[0].time_utc == "2024-01-14T14:37:36Z" and .events[0].actor == "root@pam"' <<<"$out" >/dev/null \
  || fail "backup_audit_normalise did not read the task line: $out"
pass "backup_audit_normalise reads a Proxmox task line"

if echo '{"path":"inputs/index","product":"veeam"}' | run backup_audit_normalise >/dev/null 2>&1; then
  fail "a product with no fixtures must be refused"
fi
pass "a product with no fixtures is refused by name"
