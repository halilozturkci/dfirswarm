import json, sys, xml.etree.ElementTree as ET
from pathlib import Path
from Evtx.Evtx import Evtx

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(
                r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
            )
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row: object) -> None:
        assert self._out is not None
        self._out.write(json.dumps(row, ensure_ascii=False, default=str))
        self._out.write("\n")

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(
                dir=self.path.parent, prefix=f".{self.path.name}-"
            )
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            assert self._tmp is not None
            os.replace(self._tmp, self.path)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

args = json.load(sys.stdin)
path = args['path']
event_ids = set(args.get('event_ids') or [])
contains = args.get('contains')
contains_l = contains.lower() if contains else None
limit = int(args.get('limit', 200))
start_record = args.get('start_record')
end_record = args.get('end_record')

NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

out = LosslessPage(
    "evtx_query",
    [path, sorted(event_ids), contains, start_record, end_record],
    limit,
)


def records(evtx):
    """Every record, chunk by chunk. A chunk whose record chain breaks (a length
    that points past the chunk, a header past the end of the file) ends with a
    parse_error row naming where it stopped, and the next chunk is still read:
    one malformed record must not cost the records after it, or the whole run."""
    for chunk in evtx.chunks():
        chain = chunk.records()
        while True:
            try:
                rec = next(chain)
            except StopIteration:
                break
            except Exception as e:
                yield None, {
                    'parse_error': 'the record chain of this chunk broke: %s' % e,
                    'chunk_offset': chunk.offset(),
                }
                break
            yield rec, None


with Evtx(path) as evtx:
    for rec, broken in records(evtx):
        if broken is not None:
            out.add(broken)
            continue
        xml = None
        try:
            xml = rec.xml()
            root = ET.fromstring(xml)
            sysnode = root.find('e:System', NS)
            eid_text = sysnode.findtext('e:EventID', default='', namespaces=NS) if sysnode is not None else ''
            try:
                eid = int(eid_text)
            except Exception:
                eid = None
            recid_text = sysnode.findtext('e:EventRecordID', default='', namespaces=NS) if sysnode is not None else ''
            try:
                recid = int(recid_text)
            except Exception:
                recid = None
            if start_record is not None and recid is not None and recid < int(start_record):
                continue
            if end_record is not None and recid is not None and recid > int(end_record):
                continue
            if event_ids and eid not in event_ids:
                continue
            if contains_l and contains_l not in xml.lower():
                continue
            channel = sysnode.findtext('e:Channel', default='', namespaces=NS) if sysnode is not None else ''
            computer = sysnode.findtext('e:Computer', default='', namespaces=NS) if sysnode is not None else ''
            provider = ''
            if sysnode is not None:
                p = sysnode.find('e:Provider', NS)
                if p is not None:
                    provider = p.attrib.get('Name', '')
            time_created = ''
            if sysnode is not None:
                t = sysnode.find('e:TimeCreated', NS)
                if t is not None:
                    time_created = t.attrib.get('SystemTime', '')
            eventdata = {}
            for section in ('EventData', 'UserData'):
                sec = root.find(f'e:{section}', NS)
                if sec is not None:
                    for elem in sec.iter():
                        if elem is sec:
                            continue
                        tag = elem.tag.rsplit('}', 1)[-1]
                        text = (elem.text or '').strip()
                        if not text:
                            continue
                        name = elem.attrib.get('Name') or tag
                        if name in eventdata:
                            if isinstance(eventdata[name], list):
                                eventdata[name].append(text)
                            else:
                                eventdata[name] = [eventdata[name], text]
                        else:
                            eventdata[name] = text
            out.add({
                'timestamp': time_created,
                'event_id': eid,
                'channel': channel,
                'computer': computer,
                'provider': provider,
                'record_id': recid,
                'data': eventdata,
                'xml': xml,
            })
        except Exception as e:
            out.add({
                'parse_error': str(e),
                'record_offset': rec.offset(),
                'xml': xml if isinstance(xml, str) else None,
            })
page = out.finish()
print(json.dumps({'path': path, 'count': page['matched'], 'events': out.page, **page}, ensure_ascii=False))
