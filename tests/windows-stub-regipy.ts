/**
 * A stand-in for regipy, and the means to write one hive description as either a stand-in file or real regf bytes.
 *
 * CI installs no pip package, so a test that needs the real regipy is skipped there and its assertions prove nothing. The
 * registry tools (regkv, shellbags, amcache_apps) call a small part of regipy: RegistryHive(path) with .root, .header,
 * .hive_type and .get_key(path); a key's .name, .header (last_modified, subkeys_list_offset), .subkey_count,
 * .values_count, .iter_subkeys() and .iter_values(trim_values=); a value's name, value_type, value and is_corrupted.
 * The stand-in below reads a JSON description of a hive instead of regf bytes and behaves as regipy 6.3 does for those
 * calls: a value is derived from its raw bytes by its type (a binary value is bytes, or hex trimmed to 256 characters when
 * the caller leaves trimming on; text is decoded as UTF-16LE, then UTF-8, and a type regipy does not know is decoded the
 * same way and is named by its number), "(default)" is the name of an unnamed value, a key without subkeys iterates
 * nothing, a path without a leading backslash loses its first part in get_key, and a value record that cannot be parsed
 * ends the iteration without an error.
 *
 * Each test that matters runs twice from one description: against the stand-in always, and against the real library
 * with real hive bytes (tests/windows-hive.ts) where the library is installed.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { REGIPY, stubModule } from "./windows-pack-harness.ts";
import { hive, type HiveKey } from "./windows-hive.ts";

const PY_EXCEPTIONS = `
class RegipyException(Exception):
    pass

class RegistryKeyNotFoundException(RegipyException):
    pass

class RegistryParsingException(RegipyException):
    pass

class NoRegistrySubkeysException(RegipyException):
    pass
`;

const PY_REGISTRY = String.raw`
import binascii, json
from regipy.exceptions import RegistryKeyNotFoundException, RegistryParsingException

MAX_LEN = 256
NAMES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK",
         7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR", 10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD", 16: "REG_FILETIME"}


class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _decode(data, trim, max_len=MAX_LEN):
    try:
        value = data.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        try:
            value = data.decode().rstrip("\x00")
        except Exception:
            return data
    return value[:max_len] if trim else value


class NKRecord:
    def __init__(self, hive, ident):
        spec = hive._nodes[ident]
        self._hive, self._spec = hive, spec
        self.name = spec["name"]
        kids = hive._nodes[spec["children_of"]]["children"] if spec.get("children_of") else spec.get("children", [])
        self._kids = kids
        self.subkey_count = len(kids)
        self.values_count = int(spec.get("declared_values", len(spec.get("values", []))))
        listing = spec.get("children_of", ident)
        self.header = _Obj(last_modified=int(spec.get("last_modified", 133443104000000000)),
                           subkeys_list_offset=int(listing[1:]) * 8 + 0x20 if kids else 0xFFFFFFFF)

    def iter_subkeys(self):
        if spec_broken(self._spec, "subkeys"):
            raise RegistryParsingException("Expected a known signature at the subkey list of " + self.name)
        for ident in self._kids:
            yield NKRecord(self._hive, ident)

    def iter_values(self, as_json=False, max_len=MAX_LEN, trim_values=True):
        if not self.values_count:
            return
        for v in self._spec.get("values", []):
            raw, vtype = binascii.unhexlify(v["raw"]), int(v["type"])
            name = NAMES.get(vtype, str(vtype))
            if v["name"] == "":
                shown = "(default)"
            else:
                shown = v["name"]
            if name in ("REG_SZ", "REG_EXPAND_SZ"):
                value = _decode(raw, trim_values)
            elif name in ("REG_BINARY", "REG_NONE", "REG_RESOURCE_LIST", "REG_RESOURCE_REQUIREMENTS_LIST"):
                value = binascii.b2a_hex(raw).decode()[:max_len] if trim_values else raw
            elif name == "REG_DWORD":
                value = int.from_bytes(raw[:4], "little")
            elif name == "REG_QWORD":
                value = int.from_bytes(raw[:8], "little")
            elif name == "REG_MULTI_SZ":
                value = [s for s in raw.decode("utf-16-le").split("\x00") if s]
            else:
                value = _decode(raw, trim_values)
            yield _Obj(name=shown, value_type=name, value=value, is_corrupted=False)


def spec_broken(spec, what):
    return what in spec.get("broken", [])


class RegistryHive:
    def __init__(self, hive_path, hive_type=None, partial_hive_path=None):
        try:
            with open(hive_path, "rb") as fh:
                doc = json.loads(fh.read())
            self._nodes = doc["nodes"]
            self._root = doc["root"]
        except Exception as exc:
            raise RegistryParsingException("not a registry hive: %s" % exc)
        self.name = doc.get("name", "")
        self.hive_type = doc.get("hive_type")
        self.header = _Obj(primary_sequence_num=doc.get("primary", 7), secondary_sequence_num=doc.get("secondary", 7))

    @property
    def root(self):
        return NKRecord(self, self._root)

    def get_key(self, key_path):
        if key_path == "\\":
            return self.root
        parts = key_path.split("\\")[1:] if "\\" in key_path else [key_path]
        node = self.root
        for i, part in enumerate(parts):
            found = None
            for kid in node.iter_subkeys():
                if kid.name.upper() == part.upper():
                    found = kid
                    break
            if found is None:
                raise RegistryKeyNotFoundException("Did not find subkey at " + key_path)
            node = found
        return node
`;

export const REGIPY_STUB_FILES: Record<string, string> = {
  "regipy/__init__.py": "",
  "regipy/exceptions.py": PY_EXCEPTIONS,
  "regipy/registry.py": PY_REGISTRY,
};

/** A source for regipy that is not importable: what a host without the library looks like. */
export const REGIPY_ABSENT_FILES: Record<string, string> = {
  "regipy/__init__.py": "raise ImportError('regipy is not installed on this host')\n",
};

export type Val = {
  name: string;
  /** The type as the fixtures name it, or a registry type number (6 is REG_LINK, 0x1234 is a type regipy does not know). */
  type: "sz" | "expand_sz" | "binary" | "dword" | "qword" | "multi_sz" | "none" | "link" | "resource_list" | number;
  value: string | number | bigint | Buffer | string[];
};

export type Node = {
  name: string;
  lastWritten?: bigint;
  values?: Val[];
  children?: Node[];
  /** Stand-in only: the key claims this many values (a record count that is not what the list holds). */
  declaredValues?: number;
};

const TYPE_NUMBER: Record<string, number> = { none: 0, sz: 1, expand_sz: 2, binary: 3, dword: 4, link: 6, multi_sz: 7, resource_list: 8, qword: 11 };
const u16z = (text: string): Buffer => Buffer.concat([Buffer.from(text, "utf16le"), Buffer.from([0, 0])]);

function typeNumber(v: Val): number {
  return typeof v.type === "number" ? v.type : TYPE_NUMBER[v.type];
}

/** The data bytes of a value as the registry stores them. */
function raw(v: Val): Buffer {
  switch (v.type) {
    case "sz":
    case "expand_sz":
      return u16z(v.value as string);
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
    default:
      return v.value as Buffer;
  }
}

/** The stand-in's file: a flat JSON description, so a chain a thousand keys deep is not a nested document. */
export function stubHive(root: Node, opts: { primarySeq?: number; secondarySeq?: number; mutate?: (nodes: Record<string, Record<string, unknown>>, ids: Map<Node, string>) => void } = {}): string {
  const nodes: Record<string, Record<string, unknown>> = {};
  const ids = new Map<Node, string>();
  let n = 0;
  // The tree is walked with a stack of its own: a chain of a thousand keys must not exhaust the test's recursion.
  const rootId = (() => {
    const stack: Array<{ node: Node; parent?: string }> = [{ node: root }];
    let first = "";
    while (stack.length) {
      const { node, parent } = stack.pop()!;
      const id = "n" + n++;
      ids.set(node, id);
      nodes[id] = {
        name: node.name,
        last_modified: String(node.lastWritten ?? 133_443_104_000_000_000n),
        values: (node.values ?? []).map((v) => ({ name: v.name, type: typeNumber(v), raw: raw(v).toString("hex") })),
        children: [],
        ...(node.declaredValues !== undefined ? { declared_values: node.declaredValues } : {}),
      };
      if (parent) (nodes[parent].children as string[]).push(id);
      else first = id;
      for (const child of [...(node.children ?? [])].reverse()) stack.push({ node: child, parent: id });
    }
    return first;
  })();
  opts.mutate?.(nodes, ids);
  return JSON.stringify({ root: rootId, nodes, primary: opts.primarySeq ?? 7, secondary: opts.secondarySeq ?? opts.primarySeq ?? 7 });
}

// --- real hive bytes ---------------------------------------------------------------

/** The offset of the nk cell data of the key named `name` (the first, in the file's order); throws if there is none. */
export function findKey(buf: Buffer, name: string): number {
  const bytes = Buffer.from(name, "latin1");
  for (let at = 0x1000; at + 0x4c + bytes.length <= buf.length; at++) {
    if (buf[at] === 0x6e && buf[at + 1] === 0x6b && buf.readUInt16LE(at + 0x48) === bytes.length && buf.subarray(at + 0x4c, at + 0x4c + bytes.length).equals(bytes)) return at;
  }
  throw new Error("no key named " + name);
}

/** The data offset of the `nth` value record named `name` (a "vk" cell whose name sits at 0x14), in the file's order. */
function findValue(buf: Buffer, name: string, nth = 0): number {
  const bytes = Buffer.from(name, "latin1");
  let seen = 0;
  for (let at = 0x1000; at + 0x14 + bytes.length <= buf.length; at++) {
    if (buf[at] === 0x76 && buf[at + 1] === 0x6b && buf.readUInt16LE(at + 2) === bytes.length && buf.subarray(at + 0x14, at + 0x14 + bytes.length).equals(bytes)) {
      if (seen++ === nth) return at;
    }
  }
  throw new Error("no value named " + name);
}

/** Write a registry type number into the `nth` value record of `name`: the hive writer knows six types, a hive can hold any. */
export function retype(buf: Buffer, name: string, type: number, nth = 0): void {
  buf.writeUInt32LE(type, findValue(buf, name, nth) + 12);
}

/** The key's subkey count and list, set to the list of another key: the two now share one list, which is a cycle when one is below the other. */
export function shareSubkeyList(buf: Buffer, child: string, parent: string): void {
  const p = findKey(buf, parent);
  const c = findKey(buf, child);
  buf.writeUInt32LE(buf.readUInt32LE(p + 0x14), c + 0x14);
  buf.writeUInt32LE(buf.readUInt32LE(p + 0x1c), c + 0x1c);
}

/** Damage a key's subkey list: it claims 65535 elements, which run past the end of the hive, so reading it fails. */
export function breakSubkeyList(buf: Buffer, key: string): void {
  const k = findKey(buf, key);
  const list = 0x1000 + buf.readUInt32LE(k + 0x1c) + 4;
  buf.writeUInt16LE(0xffff, list + 2);
}

/** Make a key claim `count` values. */
export function claimValues(buf: Buffer, key: string, count: number): void {
  buf.writeUInt32LE(count, findKey(buf, key) + 0x24);
}

// --- one description, two readers ---------------------------------------------------

export type Variant = {
  label: string;
  real: boolean;
  skip: string | false;
  /** Write the hive at cwd/rel and return the environment a tool needs to read it (the stand-in's module path, or none). */
  write(cwd: string, rel: string, root: Node, opts?: { primarySeq?: number; secondarySeq?: number; fileName?: string }): Promise<Record<string, string>>;
  /** Write it, then let `patch` damage it: bytes for the real library, the description for the stand-in. */
  writePatched(cwd: string, rel: string, root: Node, patch: { real: (buf: Buffer) => void; stub: (nodes: Record<string, Record<string, unknown>>, ids: Map<Node, string>) => void }): Promise<Record<string, string>>;
};

/**
 * The hive writer's description of a tree. The writer emits a key's children before its values, so the values are
 * listed here in that order (`order`), each with the type to write over it when it is one the writer does not know:
 * a value is found again in the file by its name and how many values of that name came before it.
 */
type Placed = { name: string; retype: number | null };

function toHiveKey(node: Node, order: Placed[]): HiveKey {
  const children = (node.children ?? []).map((c) => toHiveKey(c, order));
  const values = (node.values ?? []).map((v) => {
    if (v.type === "sz" || v.type === "expand_sz" || v.type === "binary" || v.type === "dword" || v.type === "qword" || v.type === "multi_sz") {
      order.push({ name: v.name, retype: null });
      return { name: v.name, type: v.type, value: v.value as never };
    }
    order.push({ name: v.name, retype: typeNumber(v) });
    return { name: v.name, type: "binary" as const, value: raw(v) };
  });
  return { name: node.name, lastWritten: node.lastWritten, values, children };
}

function applyRetypes(buf: Buffer, order: Placed[]): void {
  const before = new Map<string, number>();
  for (const p of order) {
    const nth = before.get(p.name) ?? 0;
    before.set(p.name, nth + 1);
    if (p.retype !== null) retype(buf, p.name, p.retype, nth);
  }
}

export const VARIANTS: Variant[] = [
  {
    label: "stand-in regipy",
    real: false,
    skip: false,
    async write(cwd, rel, root, opts = {}) {
      await mkdir(join(cwd, rel, ".."), { recursive: true });
      await writeFile(join(cwd, rel), stubHive(root, opts));
      return stubModule(cwd, REGIPY_STUB_FILES);
    },
    async writePatched(cwd, rel, root, patch) {
      await mkdir(join(cwd, rel, ".."), { recursive: true });
      await writeFile(join(cwd, rel), stubHive(root, { mutate: patch.stub }));
      return stubModule(cwd, REGIPY_STUB_FILES);
    },
  },
  {
    label: "real regipy",
    real: true,
    skip: REGIPY,
    async write(cwd, rel, root, opts = {}) {
      const order: Placed[] = [];
      const buf = hive(toHiveKey(root, order), opts);
      applyRetypes(buf, order);
      await mkdir(join(cwd, rel, ".."), { recursive: true });
      await writeFile(join(cwd, rel), buf);
      return {};
    },
    async writePatched(cwd, rel, root, patch) {
      const order: Placed[] = [];
      const buf = hive(toHiveKey(root, order));
      applyRetypes(buf, order);
      patch.real(buf);
      await mkdir(join(cwd, rel, ".."), { recursive: true });
      await writeFile(join(cwd, rel), buf);
      return {};
    },
  },
];
