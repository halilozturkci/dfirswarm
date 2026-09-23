/**
 * The Markdown a swarm writes, as HTML. One renderer, used by the forensic
 * report on the server and by the console's file viewer in the browser, so a
 * `work/*.md` reads the same in both — and neither reaches for a library to
 * render six constructs. It is a pure module: no DOM, no node imports.
 *
 * The vocabulary is what the agents actually write: headings, lists, tables,
 * fenced and indented code, blockquotes, rules, and inline code / bold /
 * italic / links. Anything else is escaped and shown as written, which for a
 * forensic document is the right failure: nothing is silently dropped.
 */
export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Inline: code spans first, so nothing inside one is treated as markup. */
export function inline(text: string): string {
  const spans: string[] = [];
  let out = text.replace(/`([^`]+)`/g, (_m, code: string) => {
    spans.push(`<code>${escapeHtml(code)}</code>`);
    return `\u0000${spans.length - 1}\u0000`;
  });
  out = escapeHtml(out);
  out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  out = out.replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
  out = out.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_m, label: string, href: string) =>
    // The report has no outbound links: a destination that is not in this
    // file cannot be part of the record. The text stays, the target is shown.
    /^https?:/i.test(href) ? `${label} <span class="url">(${escapeHtml(href)})</span>` : label,
  );
  return out.replace(/\u0000(\d+)\u0000/g, (_m, i: string) => spans[Number(i)]);
}

function tableRow(line: string): string[] {
  return line
    .replace(/^\||\|$/g, "")
    .split("|")
    .map((c) => c.trim());
}

const DIVIDER = /^\|?[\s:|-]+\|[\s:|-]*$/;

/**
 * Markdown to HTML, for the vocabulary the delivered reports actually use:
 * ATX headings, paragraphs, `-`/`*`/`1.` lists, fenced and indented code,
 * pipe tables, blockquotes and horizontal rules.
 */
export function markdownToHtml(markdown: string, headingOffset = 0): string {
  const lines = markdown.replace(/\r\n?/g, "\n").split("\n");
  const out: string[] = [];
  let i = 0;
  const closeList: string[] = [];
  const closeAll = () => {
    while (closeList.length) out.push(closeList.pop()!);
  };

  while (i < lines.length) {
    const line = lines[i];

    if (/^```/.test(line)) {
      closeAll();
      const body: string[] = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) body.push(lines[i++]);
      i++;
      out.push(`<pre><code>${escapeHtml(body.join("\n"))}</code></pre>`);
      continue;
    }

    if (!line.trim()) {
      closeAll();
      i++;
      continue;
    }

    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      closeAll();
      const level = Math.min(6, heading[1].length + headingOffset);
      out.push(`<h${level}>${inline(heading[2].trim())}</h${level}>`);
      i++;
      continue;
    }

    if (/^(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      closeAll();
      out.push("<hr>");
      i++;
      continue;
    }

    // A pipe table needs its divider row; without one it is just text.
    if (line.includes("|") && i + 1 < lines.length && DIVIDER.test(lines[i + 1])) {
      closeAll();
      const head = tableRow(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].includes("|") && lines[i].trim()) rows.push(tableRow(lines[i++]));
      out.push(
        `<table><thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead><tbody>${rows
          .map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`)
          .join("")}</tbody></table>`,
      );
      continue;
    }

    const bullet = /^\s*[-*+]\s+(.*)$/.exec(line);
    const numbered = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    if (bullet || numbered) {
      const tag = bullet ? "ul" : "ol";
      if (closeList.at(-1) !== `</${tag}>`) {
        closeAll();
        out.push(`<${tag}>`);
        closeList.push(`</${tag}>`);
      }
      const item = [(bullet ?? numbered)![1]];
      i++;
      // A soft-wrapped bullet continues on the next line, indented. Without
      // this the tail of the sentence becomes a paragraph outside the list,
      // which is how a "not proven" caveat ends up reading as a statement.
      while (i < lines.length && lines[i].trim() && /^\s+/.test(lines[i]) && !/^\s*([-*+]|\d+[.)])\s/.test(lines[i])) {
        item.push(lines[i++].trim());
      }
      out.push(`<li>${inline(item.join(" "))}</li>`);
      continue;
    }

    if (/^>\s?/.test(line)) {
      closeAll();
      const body: string[] = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) body.push(lines[i++].replace(/^>\s?/, ""));
      out.push(`<blockquote>${markdownToHtml(body.join("\n"), headingOffset)}</blockquote>`);
      continue;
    }

    closeAll();
    const para: string[] = [];
    while (i < lines.length && lines[i].trim() && !/^(#{1,6}\s|```|>\s?|\s*[-*+]\s|\s*\d+[.)]\s)/.test(lines[i])) {
      para.push(lines[i++]);
    }
    out.push(`<p>${inline(para.join(" ").trim())}</p>`);
  }
  closeAll();
  return out.join("\n");
}
