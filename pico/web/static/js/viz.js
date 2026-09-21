/* Renderers. Each one takes plain data from the API and returns (or fills) a
   DOM node. They are deliberately dumb: no fetching, no state. */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

const Viz = (() => {

  /* ---------- security findings ----------------------------------------- */

  function meter(audit) {
    const verdict = $("#meterVerdict");
    const score = $("#meterScore");
    const fill = $("#meterFill");
    verdict.textContent = audit.verdict;
    verdict.className = `meter-verdict v-${audit.verdict}`;
    score.textContent = `${audit.score}/100`;
    fill.className = `meter-fill f-${audit.verdict}`;
    fill.style.width = `${audit.score}%`;
    findings(audit.findings, $("#findings"));
  }

  function findings(list, host) {
    host.innerHTML = "";
    if (!list || !list.length) {
      host.append(el("li", { class: "hint", text: "Nothing to flag yet." }));
      return;
    }
    list.forEach((item, index) => {
      const node = el("li", { class: `finding ${item.level}` });
      node.style.animationDelay = `${index * 40}ms`;
      node.innerHTML = `
        <b>${escapeHtml(item.title)}<span class="code">${escapeHtml(item.code)}</span></b>
        <p>${escapeHtml(item.detail)}</p>
        ${item.fix ? `<p class="fix">&rsaquo; ${escapeHtml(item.fix)}</p>` : ""}`;
      host.append(node);
    });
  }

  /* ---------- explanations ---------------------------------------------- */

  function explanation(data, host) {
    host.innerHTML = "";
    if (!data) return;

    if (data.summary) host.append(el("p", { class: "hint", text: data.summary }));
    if (data.formula) host.append(el("pre", { class: "formula", text: data.formula }));

    const steps = data.steps || [];
    if (steps.length) {
      const list = el("ol", { class: "steps" });
      steps.forEach((step, index) => {
        const item = el("li");
        item.style.animationDelay = `${index * 45}ms`;
        if (step.name) {
          item.innerHTML = `<div><b>${escapeHtml(step.name)}</b><span>${escapeHtml(step.what || "")}</span></div>`;
        } else if (step.pair) {
          item.innerHTML = `<div><b>${escapeHtml(step.pair)} &rarr; ${escapeHtml(step.result)}</b><span>${escapeHtml(step.rule)}</span></div>`;
        } else {
          item.innerHTML = `<div><b>${escapeHtml(step.input)} &rarr; ${escapeHtml(step.output)}</b><span>${escapeHtml(step.math || "")}${step.key && step.key !== "-" ? ` &middot; key letter ${escapeHtml(step.key)}` : ""}</span></div>`;
        }
        list.append(item);
      });
      host.append(list);
      if (data.truncated) {
        host.append(el("p", { class: "inline-note", text: "Trace truncated - the rest follows the same pattern." }));
      }
    }

    ["mode_note", "iv_note", "limits", "why", "note", "caveat", "signature_note",
     "eavesdropper", "key_space", "why_not_raw", "lesson"].forEach((key) => {
      if (data[key]) {
        host.append(el("p", { class: "inline-note", text: String(data[key]) }));
      }
    });
  }

  /* ---------- JSON pretty printer --------------------------------------- */

  function json(value) {
    const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
    return escapeHtml(text)
      .replace(/(&quot;[^&]*?&quot;)(\s*:)/g, '<span class="json-key">$1</span>$2')
      .replace(/:\s*(&quot;.*?&quot;)/g, ': <span class="json-str">$1</span>')
      .replace(/:\s*(-?\d+\.?\d*)/g, ': <span class="json-num">$1</span>')
      .replace(/:\s*(true|false|null)/g, ': <span class="json-bool">$1</span>');
  }

  /* ---------- Caesar ----------------------------------------------------- */

  function caesarWheel(shift) {
    const size = 300;
    const centre = size / 2;
    const outer = [];
    const inner = [];

    for (let i = 0; i < 26; i += 1) {
      const angle = (i / 26) * Math.PI * 2 - Math.PI / 2;
      outer.push(`<text x="${(centre + Math.cos(angle) * 128).toFixed(1)}" y="${(centre + Math.sin(angle) * 128).toFixed(1)}" text-anchor="middle" dominant-baseline="central">${ALPHABET[i]}</text>`);
      inner.push(`<text x="${(centre + Math.cos(angle) * 96).toFixed(1)}" y="${(centre + Math.sin(angle) * 96).toFixed(1)}" text-anchor="middle" dominant-baseline="central">${ALPHABET[i]}</text>`);
    }

    const rotation = (shift / 26) * 360;
    return `
      <div class="wheel-wrap">
        <svg class="wheel" viewBox="0 0 ${size} ${size}" role="img" aria-label="Caesar cipher wheel set to shift ${shift}">
          <circle class="outer-ring" cx="${centre}" cy="${centre}" r="143"></circle>
          <circle class="outer-ring" cx="${centre}" cy="${centre}" r="113"></circle>
          <circle class="inner-ring" cx="${centre}" cy="${centre}" r="80"></circle>
          <g>${outer.join("")}</g>
          <g class="dial" style="transform:rotate(${-rotation}deg)">${inner.join("")}</g>
          <line class="pointer" x1="${centre}" y1="14" x2="${centre}" y2="40"></line>
          <text x="${centre}" y="${centre}" text-anchor="middle" dominant-baseline="central"
                style="font-size:26px;fill:var(--accent)">${shift}</text>
        </svg>
      </div>`;
  }

  function mappingStrip(shift, highlight = "") {
    const hits = new Set(highlight.toUpperCase().split(""));
    const pairs = ALPHABET.split("").map((letter, index) => {
      const mapped = ALPHABET[(index + shift) % 26];
      return `<div class="pair ${hits.has(letter) ? "hit" : ""}"><i>${letter}</i>${mapped}</div>`;
    });
    return `<div class="mapping">${pairs.join("")}</div>`;
  }

  /* ---------- Playfair --------------------------------------------------- */

  function playfairSquare(square, hits = []) {
    const flat = [];
    const marked = new Set(hits.map(([r, c]) => `${r},${c}`));
    square.forEach((row, r) => {
      row.forEach((letter, c) => {
        const cls = marked.has(`${r},${c}`) ? "hit" : "";
        flat.push(`<div class="${cls}">${letter}</div>`);
      });
    });
    return `<div class="square">${flat.join("")}</div>`;
  }

  /* ---------- Vigenere --------------------------------------------------- */

  function tabulaRecta(table, rowHit = -1, colHit = -1) {
    const head = ["<tr><th class=\"rowhead\"></th>"]
      .concat(ALPHABET.split("").map((l) => `<th>${l}</th>`))
      .concat(["</tr>"])
      .join("");

    const body = table.map((row, r) => {
      const cells = row.map((letter, c) => {
        let cls = "";
        if (r === rowHit && c === colHit) cls = "hit";
        else if (r === rowHit) cls = "row-hit";
        else if (c === colHit) cls = "col-hit";
        return `<td class="${cls}">${letter}</td>`;
      }).join("");
      return `<tr><th class="rowhead">${ALPHABET[r]}</th>${cells}</tr>`;
    }).join("");

    return `<div class="tabula"><table>${head}${body}</table></div>`;
  }

  /* ---------- AES state -------------------------------------------------- */

  function aesState(seed = "") {
    const bytes = [];
    for (let i = 0; i < 16; i += 1) {
      const source = seed.charCodeAt(i % Math.max(seed.length, 1)) || (i * 37 + 11);
      bytes.push(((source * 31 + i * 17) % 256).toString(16).padStart(2, "0"));
    }
    return `<div class="state-grid">${bytes.map((b) => `<span>${b}</span>`).join("")}</div>`;
  }

  function shuffleState(host) {
    $$(".state-grid span", host).forEach((cell, index) => {
      setTimeout(() => {
        cell.classList.add("flip");
        setTimeout(() => {
          cell.textContent = Math.floor(Math.random() * 256).toString(16).padStart(2, "0");
        }, 240);
        setTimeout(() => cell.classList.remove("flip"), 520);
      }, index * 26);
    });
  }

  /* ---------- frequency histogram ---------------------------------------- */

  function histogram(rows, host) {
    host.innerHTML = "";
    const max = Math.max(12, ...rows.map((r) => Math.max(r.percent, r.english)));
    const peak = Math.max(...rows.map((r) => r.percent));
    rows.forEach((row, index) => {
      const column = el("div", { class: `bar-col ${row.percent === peak && peak > 0 ? "peak" : ""}` });
      const observed = el("div", { class: "bar", title: `${row.letter}: ${row.percent}% (English ${row.english}%)` });
      const expected = el("div", { class: "bar expected", title: `English ${row.english}%` });
      observed.style.height = "0%";
      expected.style.height = "0%";
      const wrap = el("div", {
        style: "display:flex;align-items:flex-end;gap:1px;width:100%;height:100%",
      }, [observed, expected]);
      column.append(wrap, el("span", { text: row.letter }));
      host.append(column);
      setTimeout(() => {
        observed.style.height = `${(row.percent / max) * 100}%`;
        expected.style.height = `${(row.english / max) * 100}%`;
      }, 30 + index * 14);
    });
  }

  /* ---------- candidate plaintexts --------------------------------------- */

  function candidates(rows, host, onPick) {
    host.innerHTML = "";
    rows.forEach((row) => {
      const node = el("div", {
        class: `candidate ${row.rank === 1 ? "best" : ""}`,
        title: row.plaintext,
      });
      node.innerHTML = `
        <span class="k">shift ${row.shift}</span>
        <span class="s">${row.score}</span>
        <span class="t">${escapeHtml(row.plaintext)}</span>`;
      if (onPick) node.addEventListener("click", () => onPick(row));
      host.append(node);
    });
  }

  return {
    meter, findings, explanation, json, caesarWheel, mappingStrip,
    playfairSquare, tabulaRecta, aesState, shuffleState, histogram, candidates,
  };
})();
