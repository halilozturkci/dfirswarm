#!/usr/bin/env python3
"""Read a protobuf blob that arrived without its schema.

More and more of Android and iOS stores its records as protobuf rather than as
SQLite — usagestats, the newer iOS Biome streams, and a growing number of app
caches. Without the .proto file there are no field names, but the wire format
carries the field number, the type and the value, and that is usually enough to
see what is in a blob and decide whether it matters.

The wire format, which is all this needs:

    key       a varint: field number = key >> 3, wire type = key & 7
    type 0    varint         an integer, a boolean, or an enum
    type 1    64-bit         a double or a fixed64
    type 2    length-then-bytes   a string, a blob, or a nested message
    type 5    32-bit         a float or a fixed32

A type 2 field is ambiguous by design, so each one is tried as a nested message
first, then as text, then reported as bytes — and the output says which reading
was taken. A value that decodes as a nested message may still really be a
string; the field number and the context decide, not this tool.
"""
import binascii
import json
import sys

WIRE = {0: "varint", 1: "64-bit", 2: "length-delimited", 3: "group start",
        4: "group end", 5: "32-bit"}


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def varint(blob, at):
    value, shift = 0, 0
    while at < len(blob):
        byte = blob[at]
        value |= (byte & 0x7F) << shift
        at += 1
        if not byte & 0x80:
            return value, at
        shift += 7
        if shift > 63:
            break
    raise ValueError("a varint ran past the end of the buffer")


def printable(blob):
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    # Every character, not most of them: a genuine string field has no control
    # bytes in it, and a nested message almost always does — its field keys are
    # low byte values. Accepting 90 per cent reads a whole submessage as text.
    if all(c.isprintable() or c in "\n\r\t" for c in text):
        return text
    return None


def decode(blob, depth):
    fields, at = [], 0
    while at < len(blob):
        start = at
        try:
            key, at = varint(blob, at)
        except ValueError:
            fields.append({"offset": start, "error": "a key ran past the end"})
            break
        number, wire = key >> 3, key & 7
        if number == 0:
            fields.append({"offset": start, "error": "field number 0, which cannot occur: "
                                                     "this is probably not protobuf"})
            break
        entry = {"field": number, "wire_type": WIRE.get(wire, str(wire)), "offset": start}
        try:
            if wire == 0:
                value, at = varint(blob, at)
                entry["value"] = value
                if value in (0, 1):
                    entry["as_bool"] = bool(value)
                # zigzag, for sint32 and sint64
                entry["as_signed"] = (value >> 1) ^ -(value & 1)
            elif wire == 1:
                if at + 8 > len(blob):
                    raise ValueError("a 64-bit field ran past the end")
                entry["value"] = int.from_bytes(blob[at:at + 8], "little")
                entry["hex"] = blob[at:at + 8].hex()
                at += 8
            elif wire == 5:
                if at + 4 > len(blob):
                    raise ValueError("a 32-bit field ran past the end")
                entry["value"] = int.from_bytes(blob[at:at + 4], "little")
                entry["hex"] = blob[at:at + 4].hex()
                at += 4
            elif wire == 2:
                length, at = varint(blob, at)
                if at + length > len(blob):
                    raise ValueError("a length-delimited field ran past the end")
                body = blob[at:at + length]
                at += length
                entry["bytes"] = length
                nested = None
                if depth > 0 and body:
                    try:
                        nested = decode(body, depth - 1)
                        if not nested or any("error" in f for f in nested):
                            nested = None
                    except ValueError:
                        nested = None
                text = printable(body)
                if nested and not (text and length < 64):
                    entry["read_as"] = "nested message"
                    entry["message"] = nested
                elif text is not None:
                    entry["read_as"] = "text"
                    entry["text"] = text
                else:
                    entry["read_as"] = "bytes"
                    entry["hex"] = body.hex()
            elif wire in (3, 4):
                entry["note"] = "groups are deprecated and are not followed"
            else:
                raise ValueError("wire type %d is not defined" % wire)
        except ValueError as exc:
            entry["error"] = str(exc)
            fields.append(entry)
            break
        fields.append(entry)
    return fields


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if args.get("hex"):
        try:
            blob = binascii.unhexlify("".join(str(args["hex"]).split()))
        except binascii.Error as exc:
            fail("hex is not valid hexadecimal", reason=str(exc))
        source = "hex"
    else:
        path = args.get("path")
        if not isinstance(path, str) or not path:
            fail("path or hex is required: a file holding one protobuf message")
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError as exc:
            fail("cannot read that file", path=path, reason=str(exc))
        source = path
    offset = args.get("offset", 0) or 0
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        fail("offset must be a non-negative integer")
    blob = blob[offset:]
    depth = args.get("max_depth", 6)
    if not isinstance(depth, int) or isinstance(depth, bool) or depth < 0:
        fail("max_depth must be a non-negative integer")
    fields = decode(blob, depth)
    broken = [f for f in fields if "error" in f]
    strings = []
    def collect(items):
        for item in items:
            if item.get("read_as") == "text":
                strings.append({"field": item["field"], "text": item["text"]})
            for nested in item.get("message", []) or []:
                collect([nested])
    collect(fields)

    print(json.dumps({
        "source": source,
        "bytes": len(blob),
        "offset": offset,
        "fields": fields,
        "field_count": len(fields),
        "problems": broken,
        "strings": strings,
        "looks_like_protobuf": bool(fields) and not broken,
        "note": "There are no field names without the .proto file, and a length-delimited field "
                "is ambiguous by design: each one was tried as a nested message, then as text, "
                "and read_as says which reading was taken. A blob that produces errors at the "
                "first field is probably not protobuf at all.",
    }, indent=2))


if __name__ == "__main__":
    main()
