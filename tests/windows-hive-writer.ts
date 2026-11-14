/**
 * A hive writer for tests that need what tests/windows-hive.ts does not write: values of any registry type number, and values of more than
 * 16,344 bytes kept as Windows keeps them, in segments a "db" record lists. The regf layout: a 4096-byte base block, one hbin of cells; a
 * key is an "nk" cell, a value a "vk" cell, a big data value a "db" cell (signature, segment count, offset of a list of segment offsets), each
 * segment a cell of at most 16,344 bytes of data. Cells are placed in order, the root key first (regipy starts at the first cell of the
 * first hbin).
 */
export const SEGMENT = 0x3fd8;
export const REG = { sz: 1, binary: 3, dword: 4, multi_sz: 7 } as const;

/** A hive writer of the test's own: cells are placed in order, the root key first (regipy starts at the first cell of the first hbin). */
export class HiveWriter {
  private cells: Buffer[] = [Buffer.alloc(0x20)];
  private at = 0x20;

  cell(data: Buffer): number {
    const size = Math.ceil((data.length + 4) / 8) * 8;
    const c = Buffer.alloc(size);
    c.writeInt32LE(-size, 0);
    data.copy(c, 4);
    const where = this.at;
    this.cells.push(c);
    this.at += size;
    return where;
  }

  /** Replace the data of a cell written before (same size or less). */
  fill(where: number, data: Buffer): void {
    let at = 0;
    for (const c of this.cells) {
      if (at === where) {
        data.copy(c, 4);
        return;
      }
      at += c.length;
    }
    throw new Error("no cell at " + where);
  }

  static nk(name: string, opts: { root?: boolean; subkeys?: number; subkeyList?: number; values?: number; valueList?: number }): Buffer {
    const n = Buffer.from(name, "latin1");
    const nk = Buffer.alloc(0x4c + n.length);
    nk.write("nk", 0, "latin1");
    nk.writeUInt16LE((opts.root ? 0x0c : 0) | 0x20, 2);
    nk.writeBigUInt64LE(133_443_104_000_000_000n, 4);
    nk.writeUInt32LE(0xffffffff, 0x10);
    nk.writeUInt32LE(opts.subkeys ?? 0, 0x14);
    nk.writeUInt32LE(opts.subkeyList ?? 0xffffffff, 0x1c);
    nk.writeUInt32LE(0xffffffff, 0x20);
    nk.writeUInt32LE(opts.values ?? 0, 0x24);
    nk.writeUInt32LE(opts.valueList ?? 0xffffffff, 0x28);
    nk.writeUInt32LE(0xffffffff, 0x2c);
    nk.writeUInt32LE(0xffffffff, 0x30);
    nk.writeUInt16LE(n.length, 0x48);
    n.copy(nk, 0x4c);
    return nk;
  }

  static vk(name: string, type: number, size: number, offset: number): Buffer {
    const n = Buffer.from(name, "latin1");
    const vk = Buffer.alloc(0x14 + n.length);
    vk.write("vk", 0, "latin1");
    vk.writeUInt16LE(n.length, 2);
    vk.writeUInt32LE(size >>> 0, 4);
    vk.writeUInt32LE(offset >>> 0, 8);
    vk.writeUInt32LE(type, 12);
    vk.writeUInt16LE(1, 16);
    n.copy(vk, 0x14);
    return vk;
  }

  /** A value: inline when four bytes or fewer, one cell up to a segment, else a db record with its own distinct segments. */
  value(name: string, type: number, data: Buffer): number {
    if (data.length <= 4) {
      const inline = Buffer.alloc(4);
      data.copy(inline);
      return this.cell(HiveWriter.vk(name, type, (data.length | 0x80000000) >>> 0, inline.readUInt32LE(0)));
    }
    if (data.length <= SEGMENT) return this.cell(HiveWriter.vk(name, type, data.length, this.cell(data)));
    const segments: number[] = [];
    for (let i = 0; i < data.length; i += SEGMENT) segments.push(this.cell(data.subarray(i, i + SEGMENT)));
    return this.cell(HiveWriter.vk(name, type, data.length, this.db(segments)));
  }

  /** A db record over the given segment offsets (which may repeat). */
  db(segments: number[], listed = segments.length): number {
    const list = Buffer.alloc(segments.length * 4);
    segments.forEach((s, i) => list.writeUInt32LE(s, i * 4));
    const listAt = this.cell(list);
    const db = Buffer.alloc(8);
    db.write("db", 0, "latin1");
    db.writeUInt16LE(listed, 2);
    db.writeUInt32LE(listAt, 4);
    return this.cell(db);
  }

  bytes(rootOffset: number): Buffer {
    const used = Buffer.concat(this.cells);
    const hbinSize = Math.ceil((used.length + 8) / 4096) * 4096;
    const hbin = Buffer.alloc(hbinSize);
    used.copy(hbin);
    hbin.write("hbin", 0, "latin1");
    hbin.writeUInt32LE(hbinSize, 8);
    hbin.writeInt32LE(hbinSize - used.length, used.length);
    const base = Buffer.alloc(4096);
    base.write("regf", 0, "latin1");
    base.writeUInt32LE(7, 4);
    base.writeUInt32LE(7, 8);
    base.writeBigUInt64LE(133_443_104_000_000_000n, 12);
    base.writeUInt32LE(1, 0x14);
    base.writeUInt32LE(5, 0x18);
    base.writeUInt32LE(1, 0x20);
    base.writeUInt32LE(rootOffset, 0x24);
    base.writeUInt32LE(hbinSize, 0x28);
    base.writeUInt32LE(1, 0x2c);
    let checksum = 0;
    for (let i = 0; i < 127; i++) checksum = (checksum ^ base.readUInt32LE(i * 4)) >>> 0;
    base.writeUInt32LE(checksum, 0x1fc);
    return Buffer.concat([base, hbin]);
  }
}

export const u16 = (s: string): Buffer => Buffer.from(s, "utf16le");
export const multi = (strings: string[]): Buffer => Buffer.concat([...strings.map((s) => Buffer.concat([u16(s), Buffer.alloc(2)])), Buffer.alloc(2)]);

/** ROOT\K with the given values (each placed by `place`), and nothing else but `padding` bytes of one free-standing cell. */
export function hiveWith(place: (w: HiveWriter) => number[], padding = 0): Buffer {
  const w = new HiveWriter();
  const root = w.cell(HiveWriter.nk("ROOT", { root: true, subkeys: 1, subkeyList: 0, values: 0 }));
  const values = place(w);
  if (padding) w.cell(Buffer.alloc(padding, 0x50));
  const list = Buffer.alloc(values.length * 4);
  values.forEach((v, i) => list.writeUInt32LE(v, i * 4));
  const k = w.cell(HiveWriter.nk("K", { values: values.length, valueList: w.cell(list) }));
  const li = Buffer.alloc(8);
  li.write("li", 0, "latin1");
  li.writeUInt16LE(1, 2);
  li.writeUInt32LE(k, 4);
  w.fill(root, HiveWriter.nk("ROOT", { root: true, subkeys: 1, subkeyList: w.cell(li), values: 0 }));
  return w.bytes(root);
}

