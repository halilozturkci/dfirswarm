import hashlib, json, os, sys, xml.etree.ElementTree as ET
from pathlib import Path
from Evtx.Evtx import Evtx

args = json.load(sys.stdin)
path = args['path']
event_ids = set(args.get('event_ids') or [])
contains = args.get('contains')
contains_l = contains.lower() if contains else None
limit = int(args.get('limit', 200))
start_record = args.get('start_record')
end_record = args.get('end_record')

NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

root_dir = Path.cwd().resolve()
default_name = 'evtx-query-' + hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest()[:16] + '.jsonl'
result_path = Path(args.get('out_file') or ('work/' + default_name))
result_path = (root_dir / result_path).resolve() if not result_path.is_absolute() else result_path.resolve()
if result_path != root_dir and root_dir not in result_path.parents:
    raise SystemExit(json.dumps({'error': 'out_file must stay inside the run directory'}))
inputs = root_dir / 'inputs'
if result_path == inputs or inputs in result_path.parents:
    raise SystemExit(json.dumps({'error': 'out_file cannot be under inputs/'}))
result_path.parent.mkdir(parents=True, exist_ok=True)

out = []
matched = 0
with Evtx(path) as evtx, result_path.open('w', encoding='utf-8') as full:
    for rec in evtx.records():
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
            entry = {
                'timestamp': time_created,
                'event_id': eid,
                'channel': channel,
                'computer': computer,
                'provider': provider,
                'record_id': recid,
                'data': eventdata,
                'xml': xml,
            }
            full.write(json.dumps(entry, ensure_ascii=False) + '\n')
            matched += 1
            if len(out) < limit:
                out.append({k: v for k, v in entry.items() if k != 'xml'})
        except Exception as e:
            if xml is None:
                try:
                    xml = rec.xml()
                except Exception as xml_error:
                    xml = None
                    e = RuntimeError('%s; XML unavailable: %s' % (e, xml_error))
            entry = {'parse_error': str(e), 'xml': xml}
            full.write(json.dumps(entry, ensure_ascii=False) + '\n')
            matched += 1
            if len(out) < limit:
                out.append({'parse_error': str(e)})
print(json.dumps({'path': path, 'count': matched, 'returned': len(out), 'events': out,
                  'truncated': matched > len(out),
                  'result_file': os.path.relpath(result_path, root_dir)}, ensure_ascii=False))
