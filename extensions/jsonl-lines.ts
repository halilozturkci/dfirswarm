/**
 * One streaming reader for every JSON Lines file the harness verifies, reads back or keeps.
 *
 * It splits the bytes at 0x0A and nowhere else. Node's `readline` also ends a line at U+2028 and U+2029 (and at a lone CR), and
 * `JSON.stringify` writes those two characters raw, so a valid record that holds one (any evidence text can) was read as broken pieces:
 * custody reported an intact trace "edited", the report's chain check reported it broken, and `traceLineBytes` could not find the line.
 * A CR before the LF stays part of the record (a verifier hashes the record as written: a line edited to end in CRLF is an edit).
 *
 * It streams (a trace reaches gigabytes: nothing here reads a whole file), decodes each record as UTF-8 after the split, so a
 * multibyte character that spans two chunks decodes whole, and yields a last record that has no LF, saying that it had none. A
 * record's offset and length are in bytes, so a caller can find the exact bytes it hashed.
 */

export type JsonlRecord = {
  /** The record, decoded as UTF-8, without its LF (a CR before it is kept). */
  text: string;
  /** The record's own bytes, without its LF: what a hash over the record covers. */
  bytes: Buffer;
  /** Where the record starts in the file, in bytes. */
  offset: number;
  /** The record's length in bytes, without its LF. */
  length: number;
  /** False for a last record that the file ends without an LF. */
  terminated: boolean;
};

/** Every record of a byte stream, split at 0x0A only. A string chunk (a stream opened with an encoding) is taken as UTF-8 bytes. */
export async function* jsonlRecords(source: AsyncIterable<Buffer | string>): AsyncGenerator<JsonlRecord> {
  let pending: Buffer[] = [];
  let pendingLength = 0;
  let offset = 0;
  for await (const raw of source) {
    const chunk = typeof raw === "string" ? Buffer.from(raw, "utf8") : raw;
    let start = 0;
    for (;;) {
      const lf = chunk.indexOf(0x0a, start);
      if (lf < 0) {
        if (start < chunk.length) {
          pending.push(chunk.subarray(start));
          pendingLength += chunk.length - start;
        }
        break;
      }
      const piece = chunk.subarray(start, lf);
      const bytes = pending.length ? Buffer.concat([...pending, piece]) : piece;
      pending = [];
      pendingLength = 0;
      yield { text: bytes.toString("utf8"), bytes, offset, length: bytes.length, terminated: true };
      offset += bytes.length + 1;
      start = lf + 1;
    }
  }
  if (pendingLength > 0) {
    const bytes = Buffer.concat(pending);
    yield { text: bytes.toString("utf8"), bytes, offset, length: bytes.length, terminated: false };
  }
}

/** The text of every record, in order: `for await (const line of jsonlLines(stream))`. An empty line is yielded as "". */
export async function* jsonlLines(source: AsyncIterable<Buffer | string>): AsyncGenerator<string> {
  for await (const record of jsonlRecords(source)) yield record.text;
}
