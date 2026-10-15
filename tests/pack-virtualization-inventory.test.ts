/**
 * virtualization-backup-forensics: virtualization_inventory lists what configuration files and inventory exports say
 * exists. Every fixture is written from the formats' public descriptions (VMware's key = "value" files, libvirt's domain,
 * domainsnapshot and pool XML, Proxmox's configuration and storage.cfg), never from the tool's output. Held here: each
 * statement carries the file and the line or element it came from; a disk is looked up only among the files given, and
 * "not in the set" is said as that; a product file the tool does not read is listed as unsupported; the keys that can hold
 * a secret are named and never shown; XML is read with entity declarations refused; every limit is reported.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, stat, symlink } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { CANARY, INVENTORY, asJob, body, everythingBut, filesUnder, json, put, qcow2, refused, rowsOf, tool, vmsd, vmx, withCwd } from "./pack-virtualization-harness.ts";
import type { Json } from "./pack-virtualization-harness.ts";

const DOMAIN = `<domain type='kvm'>
  <name>guest1</name>
  <uuid>11111111-2222-3333-4444-555555555555</uuid>
  <memory unit='KiB'>1048576</memory>
  <vcpu placement='static'>2</vcpu>
  <os><type arch='x86_64' machine='pc-q35-8.0'>hvm</type></os>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/var/lib/libvirt/images/top.qcow2'/>
      <backingStore type='file'>
        <format type='qcow2'/>
        <source file='/var/lib/libvirt/images/mid.qcow2'/>
        <backingStore type='file'><format type='raw'/><source file='/var/lib/libvirt/images/base.img'/><backingStore/></backingStore>
      </backingStore>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='network' device='disk'>
      <driver name='qemu' type='raw'/>
      <source protocol='rbd' name='pool/volume-1'><host name='ceph.example.test' port='6789'/></source>
      <target dev='vdb' bus='virtio'/>
    </disk>
    <graphics type='vnc' port='5900' passwd='hunter2hunter2'/>
  </devices>
</domain>`;

const PVE = `#web server notes
boot: order=scsi0;ide2
cores: 2
memory: 4096
name: web01
ostype: l26
machine: q35
scsi0: local-lvm:vm-100-disk-0,size=32G
scsi1: local-lvm:vm-100-disk-1,size=100G,backup=0
ide2: local:iso/debian.iso,media=cdrom
net0: virtio=BC:24:11:AA:BB:CC,bridge=vmbr0
cipassword: $5$abcdefghijklmnopqrstuv
sshkeys: ssh-ed25519%20AAAAC3NzaC1lZDI1NTE5AAAAIexample
parent: before-upgrade
lock: snapshot

[first]
cores: 2
memory: 4096
scsi0: local-lvm:vm-100-disk-0,size=32G
snaptime: 1700000000

[before-upgrade]
cores: 2
memory: 4096
parent: first
snaptime: 1700003600
vmstate: local-lvm:vm-100-state-before-upgrade
scsi0: local-lvm:vm-100-disk-0,size=32G
`;

test("a VMware configuration: the VM, its disks (with the mode that takes a disk out of snapshots), the snapshot database, and the keys that look like credentials named and never shown", async () => {
  await withCwd(async (cwd) => {
    const SECRET = "vnc-pass-w0rd";
    await put(cwd, "inputs/vm/web.vmx", vmx([
      ["displayName", "web01"], ["guestOS", "ubuntu-64"], ["config.version", "8"], ["virtualHW.version", "19"], ["uuid.bios", "56 4d 00 01"], ["memSize", "4096"], ["numvcpus", "2"],
      ["scsi0:0.fileName", "web-000002.vmdk"], ["scsi0:0.present", "TRUE"], ["scsi0:1.fileName", "data.vmdk"], ["scsi0:1.mode", "independent-persistent"], ["ide1:0.fileName", "/vmfs/volumes/ds/iso/x.iso"],
      ["ide1:0.deviceType", "cdrom-image"], ["ethernet0.generatedAddress", "00:0c:29:aa:bb:cc"], ["ethernet0.networkName", "VM Network"],
      ["RemoteDisplay.vnc.password", SECRET], ["guestinfo.userdata", "I2Nsb3VkLWNvbmZpZw=="], ["unrelated.key", "x"],
    ]));
    await put(cwd, "inputs/vm/web.vmsd", vmsd({ snapshots: [{ index: 0, uid: "1", name: "pre-patch", disks: ["web-000001.vmdk"], high: "371234", low: "5678" }, { index: 1, uid: "2", name: "post", parent: "1", disks: ["web-000002.vmdk"] }] }));
    await put(cwd, "inputs/vm/web-000002.vmdk", "# Disk DescriptorFile\n");
    const run = await tool(INVENTORY, cwd, { root: "inputs/vm" });
    const out = body(run);
    assert.equal(out.status, "complete", out.status_basis);
    assert.deepEqual(out.counts, { vms: 1, disks: 5, snapshots: 2, datastores: 0, hosts: 0 }, "three devices and two snapshot disks");
    const vm = out.vms[0];
    assert.equal(vm.name, "web01");
    assert.equal(vm.guest_os, "ubuntu-64");
    assert.equal(vm.hardware_version, "19");
    assert.equal(vm.memory_mb, "4096");
    assert.deepEqual(vm.network_adapters, ["ethernet0"]);
    assert.equal(vm.locator.file, vm.source_id);
    const names = vm.keys_that_look_like_credentials.map((k: Json) => k.name);
    assert.deepEqual(names.sort(), ["RemoteDisplay.vnc.password", "guestinfo.userdata"].sort());
    assert.equal(vm.keys_that_look_like_credentials.find((k: Json) => k.name === "RemoteDisplay.vnc.password").value_chars, SECRET.length);
    assert.equal(vm.keys_not_shown, 4, "the two credential-like keys, unrelated.key and .encoding are counted and not shown");
    assert.equal(run.stdout.includes(SECRET), false, "no value of a credential-like key reaches the answer");
    assert.equal(run.stdout.includes("I2Nsb3VkLWNvbmZpZw"), false);
    const disks = out.disks.filter((d: Json) => d.vm === vm.id);
    const data = disks.find((d: Json) => d.file === "data.vmdk");
    assert.equal(data.mode, "independent-persistent", "the mode that takes a disk out of snapshots is shown, with its line");
    assert.equal(data.locator.line > 1, true);
    assert.equal(disks.find((d: Json) => d.file === "web-000002.vmdk").in_set, "yes");
    assert.equal(data.in_set, "no");
    assert.equal(data.how, "not_in_set");
    assert.equal(disks.find((d: Json) => d.device === "ide1:0").role, "optical or image");
    const snaps = out.snapshots;
    assert.deepEqual(snaps.map((s: Json) => [s.index, s.name, s.parent_uid]), [[0, "pre-patch", null], [1, "post", "1"]]);
    assert.equal(snaps[0].time_utc, null, "two raw fields are not decoded into a time");
    assert.deepEqual(snaps[0].time_raw, { createTimeHigh: "371234", createTimeLow: "5678" });
    assert.match(snaps[0].time_basis, /not decoded/);
    assert.equal(out.disks.filter((d: Json) => d.role === "snapshot disk").length, 2);
  });
});

test("a libvirt domain: every layer of a backing chain is a disk reference, a network disk is not looked up as a file, a console password is named and not shown", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/libvirt/guest1.xml", DOMAIN);
    await put(cwd, "inputs/libvirt/images/mid.qcow2", qcow2({}));
    const run = await tool(INVENTORY, cwd, { root: "inputs/libvirt" });
    const out = body(run);
    const vm = out.vms[0];
    assert.equal(vm.format, "libvirt_domain");
    assert.equal(vm.uuid, "11111111-2222-3333-4444-555555555555");
    assert.equal(vm.machine, "pc-q35-8.0");
    assert.equal(vm.memory, "1048576 KiB");
    assert.deepEqual(vm.credential_like_attributes, [{ where: "/domain/devices/graphics[1]@passwd", value_chars: 14 }]);
    assert.equal(run.stdout.includes("hunter2hunter2"), false);
    const layers = out.disks.filter((d: Json) => d.device === "vda").sort((a: Json, b: Json) => a.layer - b.layer);
    assert.deepEqual(layers.map((d: Json) => [d.layer, d.file, d.disk_format, d.role]), [
      [0, "/var/lib/libvirt/images/top.qcow2", "qcow2", "disk"],
      [1, "/var/lib/libvirt/images/mid.qcow2", "qcow2", "backing store"],
      [2, "/var/lib/libvirt/images/base.img", "raw", "backing store"],
    ]);
    assert.deepEqual(layers.map((d: Json) => d.locator.element), [
      "/domain/devices/disk[1]", "/domain/devices/disk[1]/backingStore", "/domain/devices/disk[1]/backingStore/backingStore"]);
    assert.equal(layers[1].in_set, "yes", "mid.qcow2 is among the files given (by file name: the path is the libvirt host's)");
    assert.equal(layers[1].how, "basename_only");
    assert.match(layers[1].in_set_note, /file name alone/);
    assert.equal(layers[0].in_set, "no");
    const net = out.disks.find((d: Json) => d.device === "vdb");
    assert.equal(net.in_set, "no_name");
    assert.equal(net.source_protocol, "rbd");
    assert.equal(net.source_name, "pool/volume-1");
  });
});

test("a libvirt snapshot, a storage pool and ESXi's vmInventory.xml: times only where the file states an epoch, and a registered VM is not a running one", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/x/snap.xml", `<domainsnapshot><name>before</name><description>d</description><state>running</state><creationTime>1700000000</creationTime><parent><name>root</name></parent><memory snapshot='internal'/><disks><disk name='vda' snapshot='external'><source file='/images/top.qcow2'/></disk></disks><domain><name>guest1</name></domain></domainsnapshot>`);
    await put(cwd, "inputs/x/pool.xml", `<pool type='dir'><name>default</name><uuid>aaaaaaaa-0000-0000-0000-000000000000</uuid><target><path>/var/lib/libvirt/images</path></target></pool>`);
    await put(cwd, "inputs/x/vmInventory.xml", `<ConfigRoot><ConfigEntry id="0001"><objID>1</objID><vmxCfgPath>/vmfs/volumes/5f1a2b3c-abcd/web/web.vmx</vmxCfgPath></ConfigEntry><ConfigEntry id="0002"><objID>2</objID><vmxCfgPath>/vmfs/volumes/ds1/db/db.vmx</vmxCfgPath></ConfigEntry></ConfigRoot>`);
    await put(cwd, "inputs/x/web/web.vmx", vmx([["displayName", "web"]]));
    const out = body(await tool(INVENTORY, cwd, { root: "inputs/x" }));
    const snap = out.snapshots.find((s: Json) => s.format === "libvirt_domainsnapshot");
    assert.equal(snap.name, "before");
    assert.equal(snap.parent_name, "root");
    assert.equal(snap.time_utc, "2023-11-14T22:13:20Z");
    assert.match(snap.time_basis, /seconds since 1970-01-01T00:00:00Z/);
    assert.equal(snap.memory, "internal");
    assert.equal(out.datastores[0].path, "/var/lib/libvirt/images");
    const inv = out.vms.filter((v: Json) => v.format === "esxi_vm_inventory_xml");
    assert.equal(inv.length, 2);
    assert.equal(inv[0].datastore_hint, "5f1a2b3c-abcd");
    assert.equal(inv[0].configuration_in_set, "yes");
    assert.equal(inv[1].configuration_in_set, "no");
    assert.match(inv[0].note, /not evidence that it ran, still exists/);
    assert.equal(inv[1].locator.element, "/ConfigRoot/ConfigEntry[2]");
  });
});

test("a Proxmox configuration: snapshot sections with their epoch times and parents, backup=0 shown, storage volumes listed and not looked up, credential-like keys named and not shown", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/pve/etc/pve/nodes/pve1/qemu-server/100.conf", PVE);
    await put(cwd, "inputs/pve/etc/pve/storage.cfg", `dir: local\n\tpath /var/lib/vz\n\tcontent iso,vztmpl,backup\n\tprune-backups keep-last=3\n\nlvmthin: local-lvm\n\tthinpool data\n\tvgname pve\n\tcontent rootdir,images\n\npbs: backup\n\tdatastore store1\n\tserver pbs.example.test\n\tusername backup@pbs\n\tfingerprint 00:11:22\n\tpassword notstoredhere\n`);
    const run = await tool(INVENTORY, cwd, { root: "inputs/pve" });
    const out = body(run);
    const vm = out.vms[0];
    assert.equal(vm.vmid, "100");
    assert.equal(vm.node, "pve1");
    assert.equal(vm.kind, "qemu");
    assert.equal(vm.lock, "snapshot");
    assert.equal(vm.current_parent_snapshot, "before-upgrade");
    assert.deepEqual(vm.snapshot_sections, ["first", "before-upgrade"]);
    assert.equal(vm.comment_lines_not_shown, 1);
    assert.deepEqual(vm.keys_that_look_like_credentials.map((k: Json) => k.name).sort(), ["cipassword", "sshkeys"]);
    assert.equal(run.stdout.includes("abcdefghijklmnopqrstuv"), false);
    assert.equal(run.stdout.includes("AAAAC3NzaC1lZDI1NTE5"), false);
    const nobackup = out.disks.find((d: Json) => d.device === "scsi1" && d.section === "current");
    assert.equal(nobackup.backup, "0");
    assert.equal(nobackup.in_set, "not_a_file", "an LVM volume is not a file in the set");
    assert.equal(nobackup.size, "100G");
    const snaps = out.snapshots;
    assert.deepEqual(snaps.map((s: Json) => [s.name, s.parent_name, s.time_utc]), [["first", null, "2023-11-14T22:13:20Z"], ["before-upgrade", "first", "2023-11-14T23:13:20Z"]]);
    assert.equal(snaps[1].vm_state_volume, "local-lvm:vm-100-state-before-upgrade");
    assert.equal(out.hosts[0].node, "pve1");
    assert.match(out.hosts[0].node_basis, /directory name in the path/);
    const stores = out.datastores;
    assert.deepEqual(stores.map((s: Json) => [s.type, s.name]), [["dir", "local"], ["lvmthin", "local-lvm"], ["pbs", "backup"]]);
    assert.equal(stores[0].settings["prune-backups"], "keep-last=3");
    assert.equal(stores[2].settings.username, "backup@pbs");
    assert.equal(stores[2].settings.password, undefined, "a password key is never shown");
    assert.equal(stores[2].keys_that_look_like_credentials.some((k: Json) => k.name === "password"), true);
    assert.equal(run.stdout.includes("notstoredhere"), false);
  });
});

test("a Proxmox configuration is recognised by its keys when it sits outside the usual path, and a container configuration is a container", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/x/copy-of-101.conf", "boot: order=scsi0\ncores: 1\nmemory: 512\nname: a\nscsi0: local:101/vm-101-disk-0.qcow2,size=4G\n");
    await put(cwd, "inputs/x/pve/lxc/200.conf", "arch: amd64\nhostname: ct1\nmemory: 512\nostype: debian\nrootfs: local-lvm:vm-200-disk-0,size=8G\n");
    await put(cwd, "inputs/x/vm-101-disk-0.qcow2", qcow2({}));
    await put(cwd, "inputs/x/unrelated.conf", "# nothing\nkey=value\n");
    const out = body(await tool(INVENTORY, cwd, { root: "inputs/x" }));
    assert.equal(out.vms.length, 2);
    assert.equal(out.vms.find((v: Json) => v.vmid === "200").kind, "container");
    const file = out.disks.find((d: Json) => d.file === "local:101/vm-101-disk-0.qcow2");
    assert.equal(file.in_set, "yes", "a file-backed volume is looked up by file name among the files given");
    assert.equal(out.other_files_by_extension[".conf"], 1, "an unrelated .conf is counted, not read");
  });
});

test("Hyper-V, VirtualBox and OVF files are listed as unsupported, not read and not guessed at; an XML file of another kind is said to be one", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/x/vm.vmcx", Buffer.from("VMCX\0\0\0"));
    await put(cwd, "inputs/x/vm.VMRS", Buffer.alloc(16));
    await put(cwd, "inputs/x/m.vbox", `<?xml version="1.0"?><VirtualBox><Machine name="x"/></VirtualBox>`);
    await put(cwd, "inputs/x/appliance.ovf", `<Envelope><References/></Envelope>`);
    await put(cwd, "inputs/x/other.xml", `<rss><channel/></rss>`);
    const out = body(await tool(INVENTORY, cwd, { root: "inputs/x" }));
    const by = Object.fromEntries(out.sources.map((s: Json) => [s.file, s]));
    for (const f of ["vm.vmcx", "vm.VMRS", "m.vbox", "appliance.ovf", "other.xml"]) assert.equal(by[f].state, "unsupported_recognised", f);
    assert.match(by["vm.vmcx"].reason, /Hyper-V virtual machine configuration/);
    assert.match(by["m.vbox"].reason, /VirtualBox/);
    assert.equal(out.counts.vms, 0);
    assert.equal(out.status, "complete", "an unsupported file is named, and does not make the read of the others partial");
    assert.match(out.status_basis, /5 file\(s\) of a recognised kind it does not read are listed as unsupported/);
  });
});

test("XML: an entity declaration is refused whatever the encoding, nesting and element counts are bounded, a truncated file is a failed file, and none of it raises", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/x/bomb.xml", `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;">]><domain><name>&c;</name></domain>`);
    await put(cwd, "inputs/x/doctype.xml", `<!DOCTYPE domain SYSTEM "file:///etc/passwd"><domain><name>x</name></domain>`);
    await put(cwd, "inputs/x/utf16.xml", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`<!DOCTYPE d [<!ENTITY a "x">]><domain><name>&a;</name></domain>`, "utf16le")]));
    await put(cwd, "inputs/x/latin1.xml", Buffer.from(`<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE d [<!ENTITY a "x">]><domain><name>&a;</name></domain>`, "latin1"));
    await put(cwd, "inputs/x/deep.xml", "<domain>" + "<a>".repeat(200) + "</a>".repeat(200) + "</domain>");
    await put(cwd, "inputs/x/wide.xml", "<domain>" + "<a/>".repeat(150_000) + "</domain>");
    await put(cwd, "inputs/x/cut.xml", `<domain><name>x</name><devices><disk type='file'`);
    await put(cwd, "inputs/x/ok.xml", `<domain type='kvm'><name>fine</name></domain>`);
    const out = body(await tool(INVENTORY, cwd, { root: "inputs/x" }));
    const by = Object.fromEntries(out.sources.map((s: Json) => [s.file, s]));
    assert.equal(by["utf16.xml"].state, "unsupported_recognised", "XML in a UTF-16 encoding is named and never handed to a parser");
    assert.match(by["utf16.xml"].reason, /UTF-16/);
    for (const f of ["bomb.xml", "doctype.xml", "latin1.xml"]) {
      assert.equal(by[f].state, "failed", f);
      assert.match(by[f].reason, /DOCTYPE or ENTITY declaration is refused/, f);
    }
    assert.equal(by["deep.xml"].state, "failed");
    assert.match(by["deep.xml"].reason, /nested deeper than 64/);
    assert.equal(by["wide.xml"].state, "failed");
    assert.match(by["wide.xml"].reason, /more than 100000 elements/);
    assert.equal(by["cut.xml"].state, "failed");
    assert.equal(by["ok.xml"].state, "parsed");
    assert.equal(out.vms.some((v: Json) => v.name === "fine"), true);
    assert.equal(out.status, "partial");
  });
});

test("a text file is read a line at a time with a cap: a line over 64 KiB is counted, a file with more lines than the cap is partial, and a NUL or non-UTF-8 byte does not raise", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/x/a.vmx", Buffer.concat([Buffer.from(`displayName = "ok"\nbig = "${"x".repeat(70_000)}"\nbinary = "a`), Buffer.from([0, 0xff, 0xfe]), Buffer.from(`b"\nguestOS = "linux"\n`)]));
    const out = body(await tool(INVENTORY, cwd, { root: "inputs/x" }));
    assert.equal(out.vms[0].name, "ok");
    assert.equal(out.vms[0].guest_os, "linux");
    assert.equal(out.status, "complete");
    const lines = Array.from({ length: 600_000 }, (_, i) => `k${i} = "v"`).join("\n");
    await put(cwd, "inputs/y/big.vmx", `displayName = "big"\n${lines}\n`);
    const big = body(await tool(INVENTORY, cwd, { root: "inputs/y" }));
    assert.equal(big.sources[0].state, "partial");
    assert.match(big.sources[0].reason, /more than 500000 lines/);
    assert.equal(big.status, "partial");
    assert.equal(big.vms[0].name, "big", "what was read before the cap is listed");
    await put(cwd, "inputs/z/huge.vmx", "displayName = \"x\"\n");
    const small = body(await tool(INVENTORY, cwd, { root: "inputs/z", max_file_bytes: 4096 }));
    assert.equal(small.status, "complete", "a file under the limit is read");
    await put(cwd, "inputs/z/over.vmx", `displayName = "${"y".repeat(5000)}"\n`);
    const over = body(await tool(INVENTORY, cwd, { root: "inputs/z", max_file_bytes: 4096 }));
    assert.equal(over.sources.find((s: Json) => s.file === "over.vmx").state, "failed");
    assert.match(over.sources.find((s: Json) => s.file === "over.vmx").reason, /over max_file_bytes/);
  });
});

test("a hundred thousand snapshots in one database or one configuration are listed to the per-file cap and the rest are counted, never silently dropped", async () => {
  await withCwd(async (cwd) => {
    const sections: string[] = ["name: big", "memory: 1"];
    for (let i = 0; i < 100_500; i++) sections.push(`[s${i}]`, "parent: p", "snaptime: 1700000000");
    await put(cwd, "inputs/x/pve/qemu-server/300.conf", sections.join("\n") + "\n");
    const started = Date.now();
    const out = body(await asJob(INVENTORY, cwd, { root: "inputs/x", limit: 10 }));
    assert.ok(Date.now() - started < 60_000);
    assert.equal(out.sources[0].state, "partial");
    assert.match(out.sources[0].reason, /more than 100000 sections/);
    assert.equal(out.status, "partial");
  });
});

test("the walk reports its limits; links and pipes are never followed or opened; a bad argument is an error document", async () => {
  await withCwd(async (cwd) => {
    for (let i = 0; i < 30; i++) await put(cwd, `inputs/x/v${i}.vmx`, vmx([["displayName", `vm${i}`]]));
    const cut = body(await tool(INVENTORY, cwd, { root: "inputs/x", max_files: 5 }));
    assert.equal(cut.files_in_set, 5);
    assert.equal(cut.status, "partial");
    assert.match(cut.walk_truncated, /max_files \(5\)/);
    await mkdir(join(cwd, "inputs/l"), { recursive: true });
    await put(cwd, "inputs/out/e.vmx", vmx([["displayName", "outside"]]));
    await symlink(join(cwd, "inputs/out/e.vmx"), join(cwd, "inputs/l/e.vmx"));
    const linked = body(await tool(INVENTORY, cwd, { root: "inputs/l" }));
    assert.equal(linked.walk.counts.links, 1);
    assert.equal(linked.counts.vms, 0);
    assert.match(refused(await tool(INVENTORY, cwd, { root: "inputs/l/e.vmx" })).error, /symlink root/);
    assert.match(refused(await tool(INVENTORY, cwd, { root: "inputs/out/e.vmx" })).error, /not a directory/);
    for (const args of [{}, { root: 3 }, { paths: [3] }, { root: "inputs/x", limit: -1 }, { root: "inputs/x", max_file_bytes: 1 }, { root: "inputs/x", write_text: 1 }]) {
      assert.equal(refused(await tool(INVENTORY, cwd, args)).status, "failed");
    }
    assert.equal(json(await tool(INVENTORY, cwd, [])).status, "failed");
  });
});

test("names and values the answer shows are shape-checked: a token, a key, user-info and a long hex run in a file name, a VM name, a disk path and a snapshot name never reach an answer or a file; the originals are in the 0600 values file only when asked, in a job", async () => {
  await withCwd(async (cwd) => {
    const C = CANARY;
    await put(cwd, `inputs/${C.github}/web.vmx`, vmx([["displayName", `vm ${C.aws}`], ["scsi0:0.fileName", `https://${C.userinfo}@h.example.test/${C.hex}.vmdk`]]));
    await put(cwd, "inputs/s.vmsd", vmsd({ snapshots: [{ index: 0, uid: "1", name: `snap ${C.github}`, disks: [`${C.hex}-000001.vmdk`] }] }));
    await put(cwd, "inputs/k.vmx", `# comment ${C.github} ${C.aws}\ndisplayName = "k"\n# ${C.hex}\n`);
    await put(cwd, "inputs/n.conf", `#notes ${C.github} ${C.userinfo}@h\nboot: order=scsi0\ncores: 1\nmemory: 1\nname: n\n`);
    await put(cwd, "inputs/c.conf", `boot: order=scsi0\ncores: 1\nmemory: 1\nname: ${C.aws}\nscsi0: local:100/${C.hex}.qcow2,size=1G\n`);
    await put(cwd, "inputs/d.xml", `<domain type='kvm'><name>${C.github}</name><devices><disk type='file'><source file='/images/${C.aws}/${C.hex}.qcow2'/><target dev='vda'/></disk></devices></domain>`);
    // fields that are not names too: every string the evidence supplies is checked, whether or not a call site names it
    await put(cwd, "inputs/f.vmx", vmx([["memSize", C.github], ["numvcpus", C.aws], ["guestOS", C.hex], ["config.version", C.github], ["virtualHW.version", C.aws], ["uuid.bios", C.hex], ["firmware", C.github], ["scsi0:0.fileName", "a.vmdk"], ["scsi0:0.present", C.aws], ["scsi0:0.mode", C.hex], ["scsi0:0.deviceType", C.github]]));
    await put(cwd, "inputs/g.xml", `<domain type='${C.github}'><name>n</name><uuid>${C.aws}</uuid><memory unit='${C.hex}'>${C.github}</memory><vcpu>${C.aws}</vcpu><os><type arch='${C.hex}' machine='${C.github}'>hvm</type></os><devices><disk type='file' device='${C.aws}'><driver name='qemu' type='${C.github}'/><source file='/x.qcow2'/><target dev='${C.hex}' bus='${C.aws}'/></disk></devices></domain>`);
    await put(cwd, "inputs/h/qemu-server/9.conf", `cores: ${C.github}\nmemory: ${C.aws}\nname: x\nostype: ${C.hex}\nmachine: ${C.github}\nlock: ${C.aws}\nscsi0: local:9/x.qcow2,size=${C.github},backup=${C.hex},media=${C.aws}\nparent: ${C.hex}\n\n[${C.github}]\nsnaptime: ${C.aws}\nparent: ${C.hex}\nsnapstate: ${C.github}\n`);
    await put(cwd, "inputs/h/storage.cfg", `${C.aws}: ${C.github}\n\tpath ${C.hex}\n\tcontent ${C.aws}\n`);
    await put(cwd, "inputs/i/vmInventory.xml", `<ConfigRoot><ConfigEntry id="${C.github}"><objID>${C.aws}</objID><vmxCfgPath>/vmfs/volumes/${C.hex}/x/x.vmx</vmxCfgPath></ConfigEntry></ConfigRoot>`);
    const run = await tool(INVENTORY, cwd, { root: "inputs", limit: 1 });
    body(run);
    const skip = (await filesUnder(join(cwd, "inputs"))).map((f) => `inputs/${f}`);
    const all = await everythingBut(cwd, run.stdout + run.stderr, skip);
    for (const needle of [C.github, C.aws, C.hex, "S3cr3tPassw0rd"]) assert.equal(all.includes(needle), false, `${needle.slice(0, 6)}... reached an answer or a file an agent reads`);
    assert.match(refused(await tool(INVENTORY, cwd, { root: "inputs", write_text: true })).error, /outside a job/);
    const job = await asJob(INVENTORY, cwd, { root: "inputs", write_text: true, limit: 1 });
    const out = body(job);
    assert.equal(out.text.contains_text_that_may_hold_secrets, true);
    assert.equal((await stat(join(cwd, "out", "inventory-values.jsonl"))).mode & 0o777, 0o600);
    const values = await readFile(join(cwd, "out", "inventory-values.jsonl"), "utf8");
    assert.ok(values.includes(C.github) && values.includes(C.aws) && values.includes("S3cr3tPassw0rd"));
    const rest = await everythingBut(cwd, job.stdout + job.stderr, [...skip, "out/inventory-values.jsonl"]);
    for (const needle of [C.github, C.aws, C.hex, "S3cr3tPassw0rd"]) assert.equal(rest.includes(needle), false, "only the values file holds the originals");
    const second = await tool(INVENTORY, cwd, { root: "inputs", write_text: true }, { JOB_ID: "j000001", OUT: join(cwd, "out") });
    assert.match(refused(second).error, /values file already exists/);
    assert.equal(await readFile(join(cwd, "out", "inventory-values.jsonl"), "utf8"), values, "an earlier values file is not overwritten");
    const rows = await rowsOf(cwd, out, "vms");
    assert.ok(rows.length >= 3, "the whole is in the paging file");
  });
});

test("an inventory of nothing it reads says so: an empty directory fails, a directory of other files is complete with zero records and says what that means", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "inputs/empty"), { recursive: true });
    const empty = json(await tool(INVENTORY, cwd, { root: "inputs/empty" }));
    assert.equal(empty.status, "failed");
    assert.equal(empty.status_basis, "the set holds no file");
    await put(cwd, "inputs/other/notes.txt", "hello");
    const other = body(await tool(INVENTORY, cwd, { root: "inputs/other" }));
    assert.equal(other.status, "complete");
    assert.match(other.status_basis, /no file of a kind this tool reads/);
    assert.match(other.status_basis, /not about the system/);
    assert.deepEqual(other.other_files_by_extension, { ".txt": 1 });
  });
});

// ---- review fixes: each test below fails on the tool as first proposed ---------------------------------------------------

/** Every 12-character piece of a secret (past a fixed prefix), in any case: none may reach what an agent reads. */
function noPiece(all: string, secret: string, from = 4): void {
  const low = all.toLowerCase();
  for (let k = from; k + 12 <= secret.length; k++) assert.equal(low.includes(secret.slice(k, k + 12).toLowerCase()), false, `a piece of ${secret.slice(0, 6)}... was shown`);
}

test("a value is withheld by shape before it is folded to lower case, a file name never shows through its extension, and Proxmox storage:user:password@host is user-info", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/vm/web.vmx", vmx([["displayName", "web"], ["scsi0:0.fileName", "d.vmdk"], ["scsi0:0.deviceType", CANARY.aws]]));
    await put(cwd, `inputs/vm/notes.${CANARY.github}`, "x");
    await put(cwd, "inputs/pve/qemu-server/101.conf", "name: db\ncores: 2\nmemory: 2048\nostype: l26\nscsi0: cephstore:svc:Pa55w0rdQ7fZx9LmK2@mon1.example.test,size=8G\n");
    const run = await tool(INVENTORY, cwd, { root: "inputs", limit: 1 });
    const out = body(run);
    assert.equal(out.other_files_by_extension["(other extensions)"], 1);
    const all = await everythingBut(cwd, run.stdout + run.stderr, (await filesUnder(join(cwd, "inputs"))).map((f) => `inputs/${f}`));
    noPiece(all, CANARY.aws);
    noPiece(all, CANARY.github);
    noPiece(all, "Pa55w0rdQ7fZx9LmK2", 0);
    const disk = (await rowsOf(cwd, out, "disks")).find((d) => d.device === "scsi0:0");
    assert.match(disk.device_type, /withheld/);
  });
});

test("credential-like attributes are named up to the cap and counted past it, never an unbounded inline list", async () => {
  await withCwd(async (cwd) => {
    const graphics = Array.from({ length: 20_001 }, () => "<graphics type='vnc' passwd='p4ssw0rd'/>").join("");
    await put(cwd, "inputs/g.xml", `<domain type='kvm'><name>g</name><devices>${graphics}</devices></domain>`);
    const run = await tool(INVENTORY, cwd, { root: "inputs" });
    const out = body(run);
    const vm = out.vms[0];
    assert.equal(vm.credential_like_attributes.length, 200);
    assert.equal(vm.credential_like_attributes_total, 20_001);
    assert.ok(run.stdout.length < 200_000, `the answer stays small: ${run.stdout.length} bytes`);
    assert.equal(run.stdout.includes("p4ssw0rd"), false);
  });
});

test("Proxmox: a [special:cloudinit] section is not a snapshot, and a credential-like key is named in a snapshot or special section too", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/pve/etc/pve/qemu-server/100.conf", [
      "name: web01", "cores: 2", "memory: 4096", "ostype: l26", "cipassword: $5$current", "parent: s1", "",
      "[s1]", "cores: 2", "snaptime: 1700000000", "cipassword: $5$insnapshot", "",
      "[special:cloudinit]", "cipassword: $5$applied", "ipconfig0: ip=dhcp", "",
    ].join("\n"));
    const out = body(await tool(INVENTORY, cwd, { root: "inputs/pve" }));
    const vm = out.vms[0];
    assert.deepEqual(vm.snapshot_sections, ["s1"]);
    assert.deepEqual(vm.special_sections, ["special:cloudinit"]);
    assert.deepEqual(out.snapshots.map((s: Json) => s.name), ["s1"], "the cloud-init section is not listed as a snapshot");
    const named = vm.keys_that_look_like_credentials.map((k: Json) => [k.name, k.section, k.line]);
    assert.deepEqual(named, [["cipassword", "current", 5], ["cipassword", "s1", 11], ["cipassword", "special:cloudinit", 14]]);
    assert.equal(JSON.stringify(out).includes("$5$"), false);
  });
});
