#!/usr/bin/env python3
"""Open a document as a container, never as a document.

A document is a box, and the question is what is inside it and what runs without
anybody clicking. Three containers, three answers:

    OOXML (.docx, .xlsm)  a ZIP. vbaProject.bin inside it is the macro project;
                          the relationship XML holds references that fetch when
                          the file opens, with no macro at all.
    OLE (.doc, .xls)      a compound file, with the macro project in a stream.
    RTF                   no container: objects are hex-encoded inline, which is
                          why a plain strings sees nothing.
    PDF                   objects, some of which run: /OpenAction, /AA,
                          /JavaScript, /Launch, and embedded file streams.

The rename check matters on its own: `.docx` cannot carry a macro and `.docm`
can, so a file named `.docx` holding a vbaProject.bin has been renamed, and that
is worth a line in the report before anything inside it is read.

Nothing here is executed, and nothing is opened with the application that made
it. This reads bytes.
"""
import json
import mmap
import os
import re
import sys
import zipfile

CODE_PARTS = ("vbaproject.bin", "vbadata.xml", "macros", "drs/", "activex")
PDF_ACTIONS = [(b"/OpenAction", "runs when the document opens"),
               (b"/AA", "an additional action, which can run on open or on a page"),
               (b"/JavaScript", "JavaScript is present"),
               (b"/JS", "JavaScript is present"),
               (b"/Launch", "launches an external program"),
               (b"/EmbeddedFile", "carries an embedded file"),
               (b"/RichMedia", "embedded media, historically an execution route"),
               (b"/SubmitForm", "sends data somewhere on submission")]
# The attributes can come in either order, so match the element and read them out.
RELATIONSHIP = re.compile(rb"<Relationship\b[^>]*/?>", re.I)
ATTRIBUTE = re.compile(rb'(\w+)="([^"]*)"')


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def probe_zip(path, extract_to):
    out = {"container": "OOXML or ZIP", "parts": [], "macro_parts": [], "external_targets": []}
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        return {"container": "ZIP", "error": "the archive will not open: %s" % exc}
    with archive:
        for index, info in enumerate(archive.infolist()):
            lowered = info.filename.lower()
            entry = {"name": info.filename, "bytes": info.file_size,
                     "compressed": info.compress_size,
                     "modified": "%04d-%02d-%02dT%02d:%02d:%02d" % info.date_time}
            if any(part in lowered for part in CODE_PARTS):
                entry["carries_code"] = True
                out["macro_parts"].append(info.filename)
                if extract_to:
                    os.makedirs(extract_to, exist_ok=True)
                    safe = "%06d-%s" % (index, re.sub(r"[^A-Za-z0-9._-]", "_", info.filename))
                    target = os.path.join(extract_to, safe)
                    with open(target, "wb") as fh:
                        fh.write(archive.read(info))
                    entry["extracted_to"] = target
            out["parts"].append(entry)
            if lowered.endswith(".rels") or lowered.endswith(".xml"):
                try:
                    body = archive.read(info)
                except (zipfile.BadZipFile, RuntimeError):
                    continue
                for element in RELATIONSHIP.finditer(body):
                    attributes = {k.lower(): v for k, v in ATTRIBUTE.findall(element.group(0))}
                    if attributes.get(b"targetmode", b"").lower() != b"external":
                        continue
                    out["external_targets"].append({
                        "part": info.filename,
                        "target": attributes.get(b"target", b"").decode("utf-8", "replace"),
                        "type": attributes.get(b"type", b"").decode("utf-8", "replace").rsplit("/", 1)[-1],
                    })
        names = {i.filename.lower() for i in archive.infolist()}
        if "word/document.xml" in names:
            out["kind"] = "Word"
        elif any(n.startswith("xl/") for n in names):
            out["kind"] = "Excel"
        elif any(n.startswith("ppt/") for n in names):
            out["kind"] = "PowerPoint"
        else:
            out["kind"] = "a plain ZIP, not an Office document"
    return out


def count_occurrences(blob, needle):
    """Count non-overlapping byte strings without copying a mapped file."""
    count = 0
    offset = 0
    while True:
        offset = blob.find(needle, offset)
        if offset < 0:
            return count
        count += 1
        offset += len(needle)


def probe_pdf(blob):
    out = {"container": "PDF", "actions": []}
    for needle, meaning in PDF_ACTIONS:
        count = count_occurrences(blob, needle)
        if count:
            out["actions"].append({"keyword": needle.decode(), "count": count, "meaning": meaning})
    out["object_streams"] = count_occurrences(blob, b"/ObjStm")
    out["encrypted"] = blob.find(b"/Encrypt") >= 0
    out["pages"] = (count_occurrences(blob, b"/Type /Page") +
                    count_occurrences(blob, b"/Type/Page"))
    if out["object_streams"]:
        out["note"] = ("Object streams are compressed, so keywords inside them are invisible to "
                       "this scan and to a plain strings. A count of zero here is not an absence.")
    return out


def probe_rtf(blob):
    objects = [m.start() for m in re.finditer(rb"\\objdata", blob)]
    return {"container": "RTF",
            "embedded_objects": len(objects),
            "object_offsets": objects,
            "ole_objects": len(re.findall(rb"\\objclass\s+([A-Za-z0-9._]+)", blob)),
            "classes": sorted({m.group(1).decode("utf-8", "replace")
                               for m in re.finditer(rb"\\objclass\s+([A-Za-z0-9._]+)", blob)}),
            "note": "RTF has no container: objects are hex-encoded inline, which is why a plain "
                    "strings sees nothing. Each offset above is the start of one."}


def probe_ole(blob):
    return {"container": "OLE compound file",
            "has_macro_marker": blob.find(b"VBA") >= 0 or blob.find(b"_VBA_PROJECT") >= 0,
            "note": "The macro project lives in a stream inside this compound file. olevba reads "
                    "it and says which subroutines run automatically; this tool only says the "
                    "project is there."}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a document to look inside")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    extract_to = args.get("extract_to")
    if extract_to is not None and (not isinstance(extract_to, str) or not extract_to):
        fail("extract_to must be a non-empty path when supplied")

    with open(path, "rb") as fh:
        head = fh.read(8)

    if head[:4] == b"PK\x03\x04":
        body = probe_zip(path, extract_to)
    else:
        with open(path, "rb") as fh:
            try:
                blob = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            except ValueError:
                fail("the file is empty", path=path)
            try:
                if head[:5] == b"%PDF-":
                    body = probe_pdf(blob)
                elif head[:5] == b"{\\rtf":
                    body = probe_rtf(blob)
                elif head == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                    body = probe_ole(blob)
                else:
                    fail("this is not a container this tool reads", path=path, head_hex=head.hex(),
                         reads=["OOXML or ZIP", "PDF", "RTF", "OLE compound file"])
            finally:
                blob.close()

    extension = os.path.splitext(path)[1].lower().lstrip(".")
    renamed = None
    if body.get("macro_parts") and extension in ("docx", "xlsx", "pptx"):
        renamed = ("This file is named .%s, which cannot carry a macro, and it holds %s. It has "
                   "been renamed." % (extension, body["macro_parts"][0]))

    print(json.dumps({
        "path": path, "bytes": os.path.getsize(path), "extension": extension or None,
        **body,
        "renamed": renamed,
        "note": "Nothing was opened with the application that made it. A macro that does not run "
                "automatically needs a user to click, which changes the story: olevba names the "
                "auto-run subroutines. An external target fetches when the document opens, with "
                "no macro at all.",
    }, indent=2))


if __name__ == "__main__":
    main()
