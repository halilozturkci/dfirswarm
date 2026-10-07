/**
 * network-forensics: pcap_summary reads classic pcap and pcapng and says what it measured.
 *
 * Every capture is built here from the pcap savefile layout and the pcapng block structure; none is the
 * output of a parser. What these cases hold the tool to: a SYN retransmission is one connection attempt seen
 * twice, a tuple aggregate is not a "session", bytes are said with the length they measure, a snap length is
 * not "no payload" (a 96-byte record holds Ethernet + IPv4 + TCP headers and 42 bytes more), a pcapng
 * interface table and every block the tool does not decode are reported, a service port is named from the
 * handshake and its basis said, and a host filter written in a different IPv6 spelling still matches.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import {
  SUMMARY, TCP, asJob, body, drop, filesUnder, frameTcp4, frameTcp6, frameUdp4, ngBlock, ngEnd, ngInterface, ngOption, ngPacket, ngSection, ngStats,
  pcapClassic, refused, ticks, tool, withCwd,
} from "./pack-network-harness.ts";
import type { Json } from "./pack-network-harness.ts";

const C = "10.0.0.5";
const S = "203.0.113.7";

test("a SYN sent again with the same sequence number is one attempt seen twice, and a new sequence number is a new one", async () => {
  await withCwd(async (cwd) => {
    const t = 1_771_070_000;
    const syn = (seq: number) => frameTcp4({ src: C, dst: S, sport: 50000, dport: 443, flags: TCP.SYN, seq });
    const cap = pcapClassic([
      { sec: t, frame: syn(1000) },
      { sec: t + 1, frame: syn(1000) }, // the retransmission: same ISN
      { sec: t + 60, frame: syn(5000) }, // the tuple used again, another ISN
      { sec: t + 60, frac: 100_000, frame: frameTcp4({ src: S, dst: C, sport: 443, dport: 50000, flags: TCP.SYN | TCP.ACK, seq: 9000, ack: 5001 }) },
    ]);
    const out = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/a.pcap", cap), with_syn_times: true }));
    assert.equal(out.tuple_conversation_count, 1);
    const row = out.tuple_conversations[0];
    assert.equal(row.syn_observations, 3, "every SYN-only packet seen");
    assert.equal(row.syn_unique, 2, "distinct (sender, sequence number) pairs");
    assert.equal(row.syn_times.length, 2, "one time per distinct SYN: the first observation");
    assert.deepEqual(row.syn_times, ["2026-02-14T11:53:20.000000Z", "2026-02-14T11:54:20.000000Z"]);
    assert.equal(row.synack_observations, 1);
    // The fields that said "sessions" and "connection starts" are gone.
    assert.equal(out.conversations, undefined);
    assert.equal(row.connection_starts, undefined);
    assert.match(out.note, /tuple/i);
  });
});

test("bytes are said with the length they measure: original frame length and captured length, per row, per talker and in total", async () => {
  await withCwd(async (cwd) => {
    const data = frameTcp4({ src: C, dst: S, sport: 50000, dport: 443, flags: TCP.PSH | TCP.ACK, payload: "x".repeat(200) }); // 254 bytes
    const cut = data.subarray(0, 96); // captured 96 of 254
    const reply = frameTcp4({ src: S, dst: C, sport: 443, dport: 50000, flags: TCP.ACK }); // 54 bytes
    const cap = pcapClassic([{ sec: 10, frame: cut, orig: data.length }, { sec: 11, frame: reply }], { snaplen: 96 });
    const out = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/b.pcap", cap) }));
    assert.equal(out.bytes_original_total, 254 + 54);
    assert.equal(out.bytes_captured_total, 96 + 54);
    const row = out.tuple_conversations[0];
    assert.equal(row.bytes_original, 308);
    assert.equal(row.bytes_captured, 150);
    const talker = out.top_talkers.find((x: Json) => x.address === C);
    assert.equal(talker.bytes_original, 254);
    assert.equal(talker.bytes_captured, 96);
    // The old output mixed the two: talkers by captured length, conversations by original.
    assert.equal(row.bytes, undefined);
  });
});

test("a 96-byte snap length is not 'no payload': what was cut is counted per packet, and what payload survived is counted", async () => {
  await withCwd(async (cwd) => {
    const whole = frameTcp4({ src: C, dst: S, sport: 50000, dport: 80, flags: TCP.PSH | TCP.ACK, payload: "GET /index.html HTTP/1.1\r\n\r\n".padEnd(40, "x") });
    assert.equal(whole.length, 94, "54 header bytes and 40 payload bytes fit in 96");
    const long = frameTcp4({ src: C, dst: S, sport: 50000, dport: 80, flags: TCP.PSH | TCP.ACK, payload: "y".repeat(300) });
    const cap = pcapClassic([{ sec: 1, frame: whole }, { sec: 2, frame: long.subarray(0, 96), orig: long.length }], { snaplen: 96 });
    const out = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/c.pcap", cap) }));
    assert.equal(out.snap_length, 96);
    assert.doesNotMatch(JSON.stringify(out.notes), /little or no payload|cannot be answered/);
    assert.equal(out.truncation.truncated_packets, 1);
    assert.equal(out.truncation.by_protocol.TCP, 1);
    assert.equal(out.truncation.bytes_cut, long.length - 96);
    assert.equal(out.payload_bytes_captured_total, 40 + 42, "40 whole, and 96 - 54 of the long one");
    assert.equal(out.packets_with_payload_captured, 2);
    // A frame padded by the link layer to 60 bytes is not payload: the IP length bounds it.
    const padded = Buffer.concat([frameTcp4({ src: C, dst: S, sport: 50000, dport: 80, flags: TCP.ACK }), Buffer.alloc(6)]);
    const cap2 = pcapClassic([{ sec: 3, frame: padded }]);
    const out2 = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/c2.pcap", cap2) }));
    assert.equal(out2.payload_bytes_captured_total, 0);
  });
});

test("a pcapng with two interfaces and a block the tool does not decode returns both interfaces and counts the block", async () => {
  await withCwd(async (cwd) => {
    const eth = frameTcp4({ src: C, dst: S, sport: 50000, dport: 443, flags: TCP.SYN, seq: 1 });
    const raw = eth.subarray(14); // link type 101 (raw IP): the IPv4 packet with no Ethernet header
    const name = (s: string) => ngOption(2, Buffer.from(s));
    const filter = ngOption(11, Buffer.concat([Buffer.from([0]), Buffer.from("tcp port 443")])); // if_filter: kind 0 = a filter string
    const file = Buffer.concat([
      ngSection(),
      ngInterface({ link: 1, snaplen: 65535, options: [name("eth0"), filter, ngOption(9, Buffer.from([6]))] }),
      ngInterface({ link: 101, snaplen: 128, options: [name("tun0"), ngOption(9, Buffer.from([9]))] }),
      ngPacket({ iface: 0, ticks: ticks(1_700_000_000, 5, 6), frame: eth }),
      ngPacket({ iface: 1, ticks: ticks(1_700_000_001, 7, 9), frame: raw }),
      ngBlock(0x7f000001, Buffer.from("not a block this tool knows")),
      ngStats({ iface: 0, recv: 10n, drop: 3n }),
    ]);
    const out = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/d.pcapng", file) }));
    assert.equal(out.format, "pcapng");
    assert.equal(out.interfaces.length, 2);
    assert.deepEqual(out.interfaces.map((i: Json) => [i.link_type_id, i.snap_length, i.name]), [[1, 65535, "eth0"], [101, 128, "tun0"]]);
    assert.deepEqual(out.interfaces.map((i: Json) => i.packets), [1, 1]);
    assert.equal(out.interfaces[0].capture_filter, "tcp port 443");
    assert.equal(out.interfaces[0].ticks_per_second, 1_000_000);
    assert.equal(out.interfaces[1].ticks_per_second, 1_000_000_000);
    // No single interface speaks for the file.
    assert.equal(out.link_type, null);
    assert.equal(out.snap_length, null);
    assert.equal(out.packets, 2);
    assert.equal(out.unsupported_blocks, 1);
    assert.equal(Object.keys(out.unsupported_block_types).length, 1);
    assert.match(Object.keys(out.unsupported_block_types)[0], /0x7f000001/);
    // The interface statistics block says what the capturing interface counted.
    assert.equal(out.interface_statistics[0].packets_received, 10);
    assert.equal(out.interface_statistics[0].packets_dropped_by_interface, 3);
    assert.equal(out.blocks.by_type.enhanced_packet, 2);
  });
});

test("an option whose length runs past its block is counted, not silently dropped", async () => {
  await withCwd(async (cwd) => {
    // An option header that declares 40 bytes where 4 remain.
    const bad = Buffer.concat([Buffer.from([0x02, 0x00, 0x28, 0x00]), Buffer.from("eth0")]);
    const frame = frameUdp4({ src: C, dst: S, sport: 5353, dport: 5353, payload: "q" });
    const file = Buffer.concat([ngSection(), ngInterface({ link: 1, options: [bad] }), ngPacket({ ticks: ticks(100, 0, 6), frame })]);
    const out = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/o.pcapng", file) }));
    assert.equal(out.packets, 1);
    assert.equal(out.malformed_options, 1);
    assert.equal(out.interfaces[0].options_malformed, 1);
  });
});

test("the service port comes from the handshake, and a port chosen by the smaller-number guess says so", async () => {
  await withCwd(async (cwd) => {
    const t = 1_700_000_000;
    // The client's ephemeral port (1500) is the smaller number; the server answers on 8080.
    const tcp = [
      { sec: t, frame: frameTcp4({ src: C, dst: S, sport: 1500, dport: 8080, flags: TCP.SYN, seq: 1 }) },
      { sec: t, frac: 1, frame: frameTcp4({ src: S, dst: C, sport: 8080, dport: 1500, flags: TCP.SYN | TCP.ACK, seq: 2, ack: 2 }) },
      { sec: t + 1, frame: frameTcp4({ src: C, dst: S, sport: 1500, dport: 8080, flags: TCP.PSH | TCP.ACK, payload: "hello" }) },
    ];
    // UDP has no handshake to read it from.
    const udp = [{ sec: t + 2, frame: frameUdp4({ src: C, dst: "198.51.100.9", sport: 40000, dport: 53, payload: "dns" }) }];
    const out = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/e.pcap", pcapClassic([...tcp, ...udp])), group: "endpoint" }));
    assert.equal(out.grouping, "endpoint");
    const tcpRow = out.endpoint_aggregates.find((r: Json) => r.protocol === "TCP");
    assert.equal(tcpRow.service_port, 8080);
    assert.equal(tcpRow.service_port_basis, "syn_destination");
    const udpRow = out.endpoint_aggregates.find((r: Json) => r.protocol === "UDP");
    assert.equal(udpRow.service_port, 53, "the smaller number, offered as a guess");
    assert.match(udpRow.service_port_basis, /guess/);
    // Rows with different bases are never merged into one.
    assert.equal(out.endpoint_aggregates.length, 2);
  });
});

test("a connection series through the endpoint view keeps one row per service and every distinct SYN", async () => {
  await withCwd(async (cwd) => {
    const t = 1_771_070_000;
    const packets = [];
    for (let i = 0; i < 6; i++) {
      packets.push({ sec: t + i * 60, frame: frameTcp4({ src: C, dst: S, sport: 50000 + i, dport: 443, flags: TCP.SYN, seq: 100 + i }) });
      packets.push({ sec: t + i * 60, frac: 1000, frame: frameTcp4({ src: C, dst: S, sport: 50000 + i, dport: 443, flags: TCP.SYN, seq: 100 + i }) }); // retransmitted at once
    }
    const out = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/f.pcap", pcapClassic(packets)), group: "endpoint", with_syn_times: true }));
    assert.equal(out.endpoint_aggregates.length, 1);
    const row = out.endpoint_aggregates[0];
    assert.equal(row.syn_observations, 12);
    assert.equal(row.syn_unique, 6);
    assert.equal(row.syn_times.length, 6);
    assert.equal(row.tuples, 6);
  });
});

test("the host filter matches an IPv6 address however it is written, and refuses text that is no address", async () => {
  await withCwd(async (cwd) => {
    const a = "2001:db8::1";
    const b = "2001:db8::2";
    const cap = pcapClassic([
      { sec: 1, frame: frameTcp6({ src: a, dst: b, sport: 40000, dport: 443, flags: TCP.SYN, seq: 7 }) },
      { sec: 2, frame: frameTcp4({ src: C, dst: S, sport: 40001, dport: 443, flags: TCP.SYN, seq: 8 }) },
    ]);
    const path = await drop(cwd, "work/v6.pcap", cap);
    const spelled = body(await tool(SUMMARY, cwd, { path, host: "2001:0DB8:0000:0000:0000:0000:0000:0001" }));
    assert.equal(spelled.tuple_conversation_count, 1);
    assert.equal(spelled.tuple_conversations[0].a, "2001:db8::1");
    assert.equal(spelled.filtered.packets_matching, 1);
    assert.equal(spelled.packets, 2, "the file's packet count is the whole file's");
    assert.match(refused(await tool(SUMMARY, cwd, { path, host: "not-an-address" })).error, /host/);
  });
});

test("aggregates past the in-memory cap are kept on disk and the answer is the same as without the cap", async () => {
  await withCwd(async (cwd) => {
    const packets = [];
    for (let i = 0; i < 40; i++) {
      const client = `10.0.${i % 4}.${10 + i}`;
      packets.push({ sec: 1_700_000_000 + i, frame: frameTcp4({ src: client, dst: S, sport: 40000 + i, dport: 443, flags: TCP.SYN, seq: i }) });
      packets.push({ sec: 1_700_000_000 + i, frac: 5, frame: frameTcp4({ src: client, dst: S, sport: 40000 + i, dport: 443, flags: TCP.PSH | TCP.ACK, payload: "z".repeat(i) }) });
      // The same tuple again after the cap has been passed: its pieces must merge.
      packets.push({ sec: 1_700_000_100 + i, frame: frameTcp4({ src: client, dst: S, sport: 40000 + i, dport: 443, flags: TCP.SYN, seq: 1000 + i }) });
    }
    const path = await drop(cwd, "work/many.pcap", pcapClassic(packets));
    const plain = body(await tool(SUMMARY, cwd, { path, top: 1000, with_syn_times: true, out_dir: "work/plain" }));
    const spilled = body(await tool(SUMMARY, cwd, { path, top: 1000, with_syn_times: true, out_dir: "work/spill", max_memory_tuples: 5 }));
    assert.equal(plain.spilled_to_disk, false);
    assert.equal(spilled.spilled_to_disk, true);
    assert.deepEqual(spilled.tuple_conversations, plain.tuple_conversations);
    assert.deepEqual(spilled.top_talkers, plain.top_talkers);
    assert.equal(spilled.tuple_conversation_count, 40);
    // The temporary database is not left behind.
    assert.deepEqual((await filesUnder(join(cwd, "work/spill"))).filter((f) => /sqlite|spill/.test(f)), []);
    const tsv = (await readFile(join(cwd, "work/spill/tuple_conversations.tsv"), "utf8")).trimEnd().split("\n");
    assert.equal(tsv.length, 41);
  });
});

test("times keep the capture's own resolution, with the raw ticks beside them", async () => {
  await withCwd(async (cwd) => {
    const frame = frameTcp4({ src: C, dst: S, sport: 1, dport: 2, flags: TCP.SYN, seq: 1 });
    const nano = pcapClassic([{ sec: 1_700_000_000, frac: 123_456_789, frame }], { nano: true });
    const out = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/ns.pcap", nano) }));
    assert.equal(out.first_packet, "2023-11-14T22:13:20.123456789Z");
    assert.deepEqual(out.first_packet_raw, { ticks: 1_700_000_000_123_456_789, ticks_per_second: 1_000_000_000, offset_seconds: 0 });
    const micro = pcapClassic([{ sec: 1_700_000_000, frac: 123_456, frame }]);
    const out2 = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/us.pcap", micro) }));
    assert.equal(out2.first_packet, "2023-11-14T22:13:20.123456Z");
    assert.match(out2.note, /several|independent/i);
  });
});

test("a capture cut off mid-record fails with what was read, and a record claiming gigabytes is refused before it is read", async () => {
  await withCwd(async (cwd) => {
    const frame = frameTcp4({ src: C, dst: S, sport: 1, dport: 2, flags: TCP.SYN, seq: 1 });
    const whole = pcapClassic([{ sec: 1, frame }, { sec: 2, frame }]);
    const cut = await drop(cwd, "work/cut.pcap", whole.subarray(0, whole.length - 5));
    const err = refused(await tool(SUMMARY, cwd, { path: cut }));
    assert.match(err.error, /truncated|malformed/);
    assert.equal(err.packets_read, 1);
    // A record header that declares a 3 GB capture length.
    const huge = Buffer.concat([pcapClassic([]), (() => { const h = Buffer.alloc(16); h.writeUInt32LE(3_000_000_000, 8); h.writeUInt32LE(3_000_000_000, 12); return h; })()]);
    const err2 = refused(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/huge.pcap", huge) }));
    assert.match(err2.reason, /captured length of 3000000000 bytes/);
  });
});

test("in a job out_dir must be under $OUT, and the complete table is written there", async () => {
  await withCwd(async (cwd) => {
    const frame = frameTcp4({ src: C, dst: S, sport: 1, dport: 2, flags: TCP.SYN, seq: 1 });
    const path = await drop(cwd, "work/j.pcap", pcapClassic([{ sec: 1, frame }]));
    const outside = refused(await asJob(SUMMARY, cwd, { path, out_dir: "work/elsewhere" }));
    assert.match(outside.error, /\$OUT/);
    const ok = body(await asJob(SUMMARY, cwd, { path, out_dir: "out/summary" }, undefined, {}, "out"));
    assert.ok((await filesUnder(join(cwd, "out/summary"))).includes("tuple_conversations.tsv"));
    assert.equal(ok.tuple_conversations_tsv, "out/summary/tuple_conversations.tsv");
  });
});

test("a frame that is not IP is counted by link type, not dropped", async () => {
  await withCwd(async (cwd) => {
    const arp = Buffer.concat([Buffer.alloc(12), Buffer.from([0x08, 0x06]), Buffer.alloc(28)]);
    const frame = frameTcp4({ src: C, dst: S, sport: 1, dport: 2, flags: TCP.SYN, seq: 1 });
    const out = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/arp.pcap", pcapClassic([{ sec: 1, frame: arp }, { sec: 2, frame }])) }));
    assert.equal(out.packets, 2);
    assert.equal(out.undissected.packets, 1);
    assert.deepEqual(out.undissected.by_link_type, { Ethernet: 1 });
  });
});

test("identical SYNs sixty seconds apart are not one SYN: folding is limited to a retransmission window", async () => {
  await withCwd(async (cwd) => {
    const t = 1_771_070_000;
    const syn = frameTcp4({ src: C, dst: S, sport: 50000, dport: 443, flags: TCP.SYN, seq: 0 });
    const cap = pcapClassic(Array.from({ length: 200 }, (_, i) => ({ sec: t + i * 60, frame: syn })));
    const out = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/a.pcap", cap), with_syn_times: true }));
    const row = out.tuple_conversations[0];
    assert.equal(row.syn_observations, 200);
    // an event takes the SYNs within 120 s of its first: 0, 60 and 120 are one, 180 starts the next
    assert.equal(row.syn_unique, 67);
    assert.equal(row.syn_folded, 200 - 67);
    assert.equal(row.syn_times.length, 67);
    assert.equal(row.syn_times[1], "2026-02-14T11:56:20.000000Z");
    assert.equal(out.syn_window_seconds, 120);
    assert.match(out.note, /within 120 seconds/);
    // and a retransmission is still folded
    const quick = pcapClassic([1, 3, 7, 15].map((d) => ({ sec: t + d, frame: syn })));
    const folded = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/b.pcap", quick), with_syn_times: true })).tuple_conversations[0];
    assert.equal(folded.syn_unique, 1);
    assert.equal(folded.syn_folded, 3);
  });
});

test("a row keeps a bounded number of SYN events and shows a bounded number of times; the whole list is in a file and the answer says what it left out", async () => {
  await withCwd(async (cwd) => {
    const t = 1_771_070_000;
    const cap = pcapClassic(Array.from({ length: 30_000 }, (_, i) => ({ sec: t + i * 300, frame: frameTcp4({ src: C, dst: S, sport: 50000, dport: 443, flags: TCP.SYN, seq: i + 1 }) })));
    const result = await tool(SUMMARY, cwd, { path: await drop(cwd, "work/flood.pcap", cap), with_syn_times: true, max_memory_tuples: 1 });
    assert.ok(result.stdout.length < 200_000, `the answer is ${result.stdout.length} bytes`);
    const out = JSON.parse(result.stdout);
    const row = out.tuple_conversations[0];
    assert.equal(row.syn_observations, 30_000);
    assert.equal(row.syn_unique, 10_000);
    assert.equal(row.syn_events_not_kept, 20_000);
    assert.equal(row.syn_unique_is_lower_bound, true);
    assert.equal(row.syn_times.length, 100);
    assert.equal(row.syn_times_omitted, 9_900);
    assert.ok(out.syn_times_file, "the whole list has a name");
    const lines = (await readFile(join(cwd, out.syn_times_file), "utf8")).trimEnd().split("\n");
    assert.equal(lines.length, 1);
    assert.equal(JSON.parse(lines[0]).syn_times.length, 10_000);
    assert.match(out.notes.join(" "), /more than 100 SYN times/);
  });
});

test("a refused run leaves no temporary aggregate file, and the same out_dir can be used again", async () => {
  await withCwd(async (cwd) => {
    const frames = Array.from({ length: 50 }, (_, i) => ({ sec: 10 + i, frame: frameTcp4({ src: C, dst: S, sport: 40000 + i, dport: 443, flags: TCP.SYN, seq: 1 }) }));
    const good = pcapClassic(frames);
    const cut = good.subarray(0, good.length - 9); // a capture that ends inside a packet
    const failed = refused(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/cut.pcap", cut), out_dir: "work/o", max_memory_tuples: 1 }));
    assert.match(failed.error, /malformed or truncated/);
    const left = await filesUnder(join(cwd, "work/o")).catch(() => [] as string[]);
    assert.deepEqual(left, [], "no .pcap_summary-spill file stays behind");
    const again = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/good.pcap", good), out_dir: "work/o", max_memory_tuples: 1 }));
    assert.equal(again.packets, 50);
    assert.equal(again.spilled_to_disk, true);
    assert.deepEqual((await filesUnder(join(cwd, "work/o"))).filter((f) => f.includes("spill")), []);
  });
  await withCwd(async (cwd) => {
    const frames = Array.from({ length: 50 }, (_, i) => ({ sec: 10 + i, frame: frameTcp4({ src: C, dst: S, sport: 40000 + i, dport: 443, flags: TCP.SYN, seq: 1 }) }));
    const cut = pcapClassic(frames).subarray(0, -9);
    const failed = refused(await asJob(SUMMARY, cwd, { path: await drop(cwd, "work/cut.pcap", cut), max_memory_tuples: 1 }));
    assert.match(failed.error, /malformed or truncated/);
    assert.deepEqual((await filesUnder(join(cwd, "out"))).filter((f) => f.includes("spill")), [], "nothing is left at the root of $OUT");
  });
});

test("the link-type field's FCS bits are not part of the type, a section header's options and an interface's drop counts are read, and 1 ns apart is 1 ns", async () => {
  await withCwd(async (cwd) => {
    const frame = frameTcp4({ src: C, dst: S, sport: 50000, dport: 443, flags: TCP.SYN, seq: 1 });
    // the field is 0x20000001: Ethernet with a high bit set that is not a type; with bit 26 and a length of 2 words: an FCS of 4 bytes
    const plain = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/a.pcap", pcapClassic([{ sec: 1, frame }], { link: 0x20000001 })) }));
    assert.equal(plain.link_type, "Ethernet");
    assert.equal(plain.link_type_id, 1);
    assert.equal(plain.protocols.TCP, 1, "the frames are dissected");
    assert.equal(plain.interfaces[0].link_type_field_raw, 0x20000001);
    const fcs = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/b.pcap", pcapClassic([{ sec: 1, frame }], { link: 0x24000001 | (2 << 28) })) }));
    assert.equal(fcs.interfaces[0].fcs_length_bytes, 4);
    assert.equal(fcs.link_type, "Ethernet");
  });
  await withCwd(async (cwd) => {
    const u64 = (n: bigint): Buffer => { const b = Buffer.alloc(8); b.writeBigUInt64LE(n, 0); return b; };
    const shb = ngBlock(0x0a0d0d0a, Buffer.concat([
      (() => { const h = Buffer.alloc(16); h.writeUInt32LE(0x1a2b3c4d, 0); h.writeUInt16LE(1, 4); h.writeUInt16LE(0, 6); h.writeBigInt64LE(-1n, 8); return h; })(),
      ngOption(2, Buffer.from("x86_64")), ngOption(3, Buffer.from("Linux 6.1")), ngOption(4, Buffer.from("dumpcap 4.2")), Buffer.alloc(4),
    ]));
    const idb = ngInterface({ options: [ngOption(9, Buffer.from([9]))] }); // if_tsresol = 10^-9
    const frame = frameTcp4({ src: C, dst: S, sport: 50000, dport: 443, flags: TCP.SYN, seq: 1 });
    const padded = Buffer.concat([frame, Buffer.alloc((4 - (frame.length % 4)) % 4)]);
    const epb = (t: bigint, drops?: bigint): Buffer => {
      const head = Buffer.alloc(20);
      head.writeUInt32LE(0, 0); head.writeUInt32LE(Number(t >> 32n), 4); head.writeUInt32LE(Number(t & 0xffffffffn), 8);
      head.writeUInt32LE(frame.length, 12); head.writeUInt32LE(frame.length, 16);
      return ngBlock(6, Buffer.concat([head, padded, ...(drops !== undefined ? [ngOption(4, u64(drops)), ngEnd()] : [])]));
    };
    const stats = (() => { const h = Buffer.alloc(12); h.writeUInt32LE(0, 0); const t = ticks(1_700_000_001, 0, 9); h.writeUInt32LE(Number(t >> 32n), 4); h.writeUInt32LE(Number(t & 0xffffffffn), 8); return ngBlock(5, Buffer.concat([h, ngOption(5, u64(7n)), ngEnd()])); })();
    const base = ticks(1_700_000_000, 0, 9);
    const file = Buffer.concat([shb, idb, epb(base, 5n), epb(base + 1n), stats]);
    const out = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/c.pcapng", file) }));
    assert.deepEqual(out.section_options, [{ section: 0, hardware: "x86_64", os: "Linux 6.1", application: "dumpcap 4.2" }]);
    assert.equal(out.interfaces[0].epb_dropcount_total, 5);
    assert.equal(out.interface_statistics[0].packets_dropped_by_interface, 7);
    assert.equal(out.interface_statistics[0].time_utc, "2023-11-14T22:13:21.000000000Z");
    assert.equal(out.duration_ns, 1);
    assert.equal(out.duration_seconds, 1e-9);
  });
});

test("a frame under stacked VLAN tags (802.1ad and the legacy 0x9100) is dissected", async () => {
  await withCwd(async (cwd) => {
    const inner = frameTcp4({ src: C, dst: S, sport: 50000, dport: 443, flags: TCP.SYN, seq: 1 });
    const tagged = (outer: number): Buffer => {
      const eth = Buffer.from(inner.subarray(0, 12));
      const tags = Buffer.alloc(10);
      tags.writeUInt16BE(outer, 0); tags.writeUInt16BE(100, 2); // outer tag
      tags.writeUInt16BE(0x8100, 4); tags.writeUInt16BE(200, 6); // inner tag
      tags.writeUInt16BE(0x0800, 8);
      return Buffer.concat([eth, tags, inner.subarray(14)]);
    };
    for (const outer of [0x88a8, 0x9100]) {
      const out = body(await tool(SUMMARY, cwd, { path: await drop(cwd, `work/q${outer}.pcap`, pcapClassic([{ sec: 1, frame: tagged(outer) }])) }));
      assert.equal(out.protocols.TCP, 1, `0x${outer.toString(16)}`);
      assert.equal(out.undissected.packets, 0);
    }
  });
});

test("endpoint rows for one service are one row even when only some of its tuples show the handshake, and the answer says what the filter and the top lists count", async () => {
  await withCwd(async (cwd) => {
    const t = 1_771_070_000;
    const cap = pcapClassic([
      { sec: t, frame: frameTcp4({ src: C, dst: S, sport: 50000, dport: 443, flags: TCP.SYN, seq: 1 }) },
      { sec: t + 1, frame: frameTcp4({ src: C, dst: S, sport: 50001, dport: 443, flags: TCP.PSH | TCP.ACK, seq: 1, payload: "abc" }) },
      { sec: t + 2, frame: frameTcp4({ src: S, dst: C, sport: 443, dport: 50002, flags: TCP.SYN | TCP.ACK, seq: 1 }) },
    ]);
    const out = body(await tool(SUMMARY, cwd, { path: await drop(cwd, "work/e.pcap", cap), group: "endpoint", host: C, with_starts: true }));
    assert.equal(out.endpoint_aggregate_count, 1, JSON.stringify(out.endpoint_aggregates.map((r: Json) => [r.service_port, r.service_port_basis])));
    const row = out.endpoint_aggregates[0];
    assert.equal(row.service_port_basis, "syn_destination");
    assert.equal(row.service_port_bases.length, 3);
    assert.equal(row.tuples, 3);
    assert.match(out.filtered.applies_to, /NOT to packets/);
    assert.match(out.top_talkers_basis, /SOURCE/);
    assert.match(out.top_ports_basis, /DESTINATION/);
    assert.match(out.notes.join(" "), /with_starts is the old name of with_syn_times/);
  });
});
