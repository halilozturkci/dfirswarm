/**
 * A registry hive written from the regf layout, with regipy and every other reader
 * left out of the loop (tests/pack-windows-forensics.test.ts builds its hive fixtures
 * with it).
 */
const u16z = (text: string): Buffer => Buffer.concat([Buffer.from(text, "utf16le"), Buffer.from([0, 0])]);

/**
 * A registry hive written from the regf layout, with regipy and every other reader
 * left out of the loop. A 4096-byte base block ("regf", the two sequence numbers, the
 * version, the root cell offset, the size of the hive bins, a checksum that is the XOR
 * of the first 127 dwords); then one hbin ("hbin", its offset and size, 24 reserved
 * bytes) of cells. A cell is a negative 32-bit size (allocated), its data, padded to 8
 * bytes. A key is an "nk" cell (flags 0x2C for the root, 0x20 for a key whose name is
 * ASCII; the last-written FILETIME; the parent, subkey count and "li" list, value count
 * and value list; the name); a value is a "vk" cell (name length, data size with the top
 * bit set when the data is inline in the offset field, the type, flags 1 for an ASCII name).
 */
export type HiveValue = { name: string; type: "sz" | "expand_sz" | "binary" | "dword" | "qword" | "multi_sz"; value: string | number | bigint | Buffer | string[] };
export type HiveKey = { name: string; lastWritten?: bigint; values?: HiveValue[]; children?: HiveKey[] };

const REG_TYPE = { sz: 1, expand_sz: 2, binary: 3, dword: 4, multi_sz: 7, qword: 11 } as const;

function hiveValueData(v: HiveValue): Buffer {
  switch (v.type) {
    case "sz":
    case "expand_sz":
      return u16z(v.value as string);
    case "binary":
      return v.value as Buffer;
    case "dword": {
      const b = Buffer.alloc(4);
      b.writeUInt32LE(v.value as number);
      return b;
    }
    case "qword": {
      const b = Buffer.alloc(8);
      b.writeBigUInt64LE(BigInt(v.value as bigint));
      return b;
    }
    case "multi_sz":
      return Buffer.concat([...(v.value as string[]).map((s) => u16z(s)), Buffer.from([0, 0])]);
  }
}

export function hive(root: HiveKey, opts: { primarySeq?: number; secondarySeq?: number; fileName?: string } = {}): Buffer {
  const cells: Buffer[] = [Buffer.alloc(0x20)]; // the hbin header occupies the first 0x20 bytes
  let at = 0x20;
  const pending: Array<{ child: number; parent: number }> = [];
  const cell = (data: Buffer): number => {
    const size = Math.ceil((data.length + 4) / 8) * 8;
    const c = Buffer.alloc(size);
    c.writeInt32LE(-size, 0);
    data.copy(c, 4);
    const where = at;
    cells.push(c);
    at += size;
    return where;
  };
  // The root key is the first cell of the first hbin (regipy, like the kernel's reader, starts there),
  // so its cell is reserved before anything else is written and filled in last.
  const rootName = Buffer.from(root.name, "latin1");
  const reservedRoot = cell(Buffer.alloc(0x4c + rootName.length));
  const key = (k: HiveKey, isRoot: boolean): number => {
    const childOffsets = (k.children ?? []).map((c) => key(c, false));
    let listOffset = 0xffffffff;
    if (childOffsets.length) {
      const li = Buffer.alloc(4 + childOffsets.length * 4);
      li.write("li", 0, "latin1");
      li.writeUInt16LE(childOffsets.length, 2);
      childOffsets.forEach((o, i) => li.writeUInt32LE(o, 4 + i * 4));
      listOffset = cell(li);
    }
    const valueOffsets = (k.values ?? []).map((v) => {
      const data = hiveValueData(v);
      const name = Buffer.from(v.name, "latin1");
      const vk = Buffer.alloc(0x14 + name.length);
      vk.write("vk", 0, "latin1");
      vk.writeUInt16LE(name.length, 2);
      if (data.length <= 4) {
        vk.writeUInt32LE((data.length | 0x80000000) >>> 0, 4);
        data.copy(vk, 8);
      } else {
        vk.writeUInt32LE(data.length, 4);
        vk.writeUInt32LE(cell(data), 8);
      }
      vk.writeUInt32LE(REG_TYPE[v.type], 12);
      vk.writeUInt16LE(1, 16);
      name.copy(vk, 0x14);
      return cell(vk);
    });
    let valuesListOffset = 0xffffffff;
    if (valueOffsets.length) {
      const list = Buffer.alloc(valueOffsets.length * 4);
      valueOffsets.forEach((o, i) => list.writeUInt32LE(o, i * 4));
      valuesListOffset = cell(list);
    }
    const name = Buffer.from(k.name, "latin1");
    const nk = Buffer.alloc(0x4c + name.length);
    nk.write("nk", 0, "latin1");
    nk.writeUInt16LE(isRoot ? 0x2c : 0x20, 2);
    nk.writeBigUInt64LE(k.lastWritten ?? 133_443_104_000_000_000n, 4);
    nk.writeUInt32LE(0xffffffff, 0x10); // parent, patched below
    nk.writeUInt32LE(childOffsets.length, 0x14);
    nk.writeUInt32LE(listOffset, 0x1c);
    nk.writeUInt32LE(0xffffffff, 0x20);
    nk.writeUInt32LE((k.values ?? []).length, 0x24);
    nk.writeUInt32LE(valuesListOffset, 0x28);
    nk.writeUInt32LE(0xffffffff, 0x2c);
    nk.writeUInt32LE(0xffffffff, 0x30);
    nk.writeUInt16LE(name.length, 0x48);
    name.copy(nk, 0x4c);
    let me: number;
    if (isRoot) {
      me = reservedRoot;
      const placed = cells[1]; // cells[0] is the hbin header; the reserved root cell is the next
      placed.writeInt32LE(-placed.length, 0);
      nk.copy(placed, 4);
    } else {
      me = cell(nk);
    }
    for (const c of childOffsets) pending.push({ child: c, parent: me });
    return me;
  };
  const rootOffset = key(root, true);
  const used = Buffer.concat(cells);
  const hbinSize = Math.ceil((used.length + 8) / 4096) * 4096;
  const hbin = Buffer.alloc(hbinSize);
  used.copy(hbin);
  hbin.write("hbin", 0, "latin1");
  hbin.writeUInt32LE(0, 4);
  hbin.writeUInt32LE(hbinSize, 8);
  hbin.writeInt32LE(hbinSize - used.length, used.length); // the rest of the bin is one free cell (positive size)
  for (const { child, parent } of pending) hbin.writeUInt32LE(parent, child + 4 + 0x10);
  const base = Buffer.alloc(4096);
  base.write("regf", 0, "latin1");
  base.writeUInt32LE(opts.primarySeq ?? 7, 4);
  base.writeUInt32LE(opts.secondarySeq ?? opts.primarySeq ?? 7, 8);
  base.writeBigUInt64LE(133_443_104_000_000_000n, 12);
  base.writeUInt32LE(1, 0x14);
  base.writeUInt32LE(5, 0x18);
  base.writeUInt32LE(0, 0x1c);
  base.writeUInt32LE(1, 0x20);
  base.writeUInt32LE(rootOffset, 0x24);
  base.writeUInt32LE(hbinSize, 0x28);
  base.writeUInt32LE(1, 0x2c);
  base.write(opts.fileName ?? "\\??\\C:\\fixture\\hive", 0x30, "utf16le");
  let checksum = 0;
  for (let i = 0; i < 127; i++) checksum = (checksum ^ base.readUInt32LE(i * 4)) >>> 0;
  base.writeUInt32LE(checksum, 0x1fc);
  return Buffer.concat([base, hbin]);
}
