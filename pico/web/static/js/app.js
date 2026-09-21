/* Wires the console together: one section per tab, plus the global chrome. */

const State = {
  algorithms: [],
  algorithm: "aes",
  keySource: "password",
  rsaPair: null,
  lastPackage: null,
  lastAudit: null,
  breakAlgorithm: "caesar",
  learnTopic: "caesar",
  tabula: null,
  ivHistory: [],
};

const CLASSICAL = new Set(["caesar", "vigenere", "playfair"]);
const PUBLIC_KEY = new Set(["rsa", "hybrid"]);

/* ==========================================================================
   Global chrome
   ========================================================================== */

function initChrome() {
  applyTheme(STORE.get("pico.theme", "www"));
  $("#swatches").addEventListener("click", (event) => {
    const swatch = event.target.closest(".swatch");
    if (swatch) applyTheme(swatch.dataset.theme);
  });

  const crt = $("#crtToggle");
  const crtOn = STORE.get("pico.crt", "1") === "1";
  document.body.classList.toggle("crt", crtOn);
  setToggle(crt, crtOn);
  crt.addEventListener("click", () => {
    const on = !document.body.classList.contains("crt");
    document.body.classList.toggle("crt", on);
    setToggle(crt, on, "pico.crt");
  });

  const globeBtn = $("#globeToggle");
  const globeOn = STORE.get("pico.globe", "1") === "1";
  setToggle(globeBtn, globeOn);
  if (!globeOn) Globe.stop();
  globeBtn.addEventListener("click", () => {
    const on = !Globe.isRunning();
    if (on) Globe.start(); else Globe.stop();
    setToggle(globeBtn, on, "pico.globe");
  });

  $("#tabs").addEventListener("click", (event) => {
    const tab = event.target.closest(".tab");
    if (tab) showView(tab.dataset.view);
  });
  showView(STORE.get("pico.view", "encrypt"));

  const dialog = $("#helpDialog");
  $("#helpBtn").addEventListener("click", () => dialog.showModal());
  $("#helpClose").addEventListener("click", () => dialog.close());

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-copy]");
    if (!button) return;
    const source = $(button.dataset.copy);
    if (source) copyText(source.textContent, button);
  });

  window.addEventListener("keydown", (event) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName);
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      runCurrentView();
      return;
    }
    if (typing || event.ctrlKey || event.metaKey || event.altKey) return;
    const views = ["encrypt", "decrypt", "keys", "agent", "learn", "break"];
    if (/^[1-6]$/.test(event.key)) {
      showView(views[Number(event.key) - 1]);
    } else if (event.key.toLowerCase() === "t") {
      nextTheme();
    } else if (event.key.toLowerCase() === "c") {
      $("#crtToggle").click();
    } else if (event.key.toLowerCase() === "g") {
      $("#globeToggle").click();
    } else if (event.key === "?") {
      $("#helpDialog").showModal();
    }
  });
}

function runCurrentView() {
  const button = {
    encrypt: "#encryptBtn", decrypt: "#decryptBtn", keys: "#genAesBtn",
    agent: "#agentSend", break: "#breakBtn",
  }[currentView()];
  if (button) $(button).click();
}

/* ==========================================================================
   Encrypt
   ========================================================================== */

async function initEncrypt() {
  const { algorithms } = await API.algorithms();
  State.algorithms = algorithms;

  const grid = $("#algoGrid");
  grid.innerHTML = "";
  algorithms.forEach((algorithm) => {
    const card = el("button", {
      class: "algo-card",
      "data-algo": algorithm.id,
      "aria-pressed": String(algorithm.id === State.algorithm),
      type: "button",
    });
    card.innerHTML = `
      <b>${escapeHtml(algorithm.label)}</b>
      <span>${escapeHtml(algorithm.blurb)}</span>
      <span class="tag ${algorithm.strength === "strong" ? "strong" : "broken"}">
        ${algorithm.strength === "strong" ? "recommended" : "educational"}
      </span>`;
    card.addEventListener("click", () => selectAlgorithm(algorithm.id));
    grid.append(card);
  });

  $("#keySourceChips").addEventListener("click", (event) => {
    const chip = event.target.closest(".chip");
    if (!chip) return;
    State.keySource = chip.dataset.source;
    $$("#keySourceChips .chip").forEach((other) => {
      other.setAttribute("aria-pressed", String(other === chip));
    });
    const labels = {
      password: "Password", phrase: "Passphrase",
      mobile: "Mobile number", raw: "Raw key (base64)",
    };
    $("#secretLabel").textContent = labels[State.keySource];
    const input = $("#encSecret");
    input.type = State.keySource === "raw" ? "text" : "password";
    input.placeholder = {
      password: "tuesday-blue-42",
      phrase: "three random words beat one clever one",
      mobile: "+91 98765 43210",
      raw: "base64 of 16, 24 or 32 bytes",
    }[State.keySource];
    refreshAudit();
  });

  $("#revealSecret").addEventListener("click", () => {
    const input = $("#encSecret");
    const hidden = input.type === "password";
    input.type = hidden ? "text" : "password";
    $("#revealSecret").textContent = hidden ? "hide" : "show";
  });

  $("#encShift").addEventListener("input", (event) => {
    $("#shiftValue").textContent = event.target.value;
    refreshPreview();
  });

  const onEdit = debounce(() => { refreshAudit(); refreshPreview(); }, 280);
  ["#encMessage", "#encSecret", "#encKey"].forEach((id) => {
    $(id).addEventListener("input", onEdit);
  });
  $("#encMessage").addEventListener("input", (event) => {
    $("#encCount").textContent = `${event.target.value.length} chars`;
  });
  ["#encMode", "#encBits", "#encKdf"].forEach((id) => {
    $(id).addEventListener("change", () => { refreshAudit(); updateStatus(); });
  });

  $("#encryptBtn").addEventListener("click", doEncrypt);
  $("#encClear").addEventListener("click", () => {
    $("#encMessage").value = "";
    $("#encSecret").value = "";
    $("#encCount").textContent = "0 chars";
    $("#resultPanel").hidden = true;
    $("#encExplainPanel").hidden = true;
    refreshAudit();
  });
  $("#encSample").addEventListener("click", () => {
    $("#encMessage").value = "Meet me by the old bridge at midnight. Bring the map.";
    $("#encCount").textContent = `${$("#encMessage").value.length} chars`;
    $("#encSender").value = "Alice";
    $("#encRecipient").value = "Bob";
    if (CLASSICAL.has(State.algorithm)) {
      $("#encKey").value = State.algorithm === "playfair" ? "MONARCHY" : "LEMON";
    } else {
      $("#encSecret").value = "tuesday-blue-42";
    }
    refreshAudit();
    refreshPreview();
    toast("Example loaded");
  });

  $("#useMyKey").addEventListener("click", () => {
    if (!State.rsaPair) {
      toast("Generate an RSA pair on the Keys tab first.", "err");
      showView("keys");
      return;
    }
    $("#encPublicPem").value = State.rsaPair.public_pem;
    toast("Public key filled in");
  });

  $("#downloadPkg").addEventListener("click", () => {
    if (!State.lastPackage) return;
    const blob = new Blob([JSON.stringify(State.lastPackage, null, 2)],
      { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = el("a", {
      href: url,
      download: `pico-package-${Date.now()}.json`,
    });
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    toast("Package downloaded", "ok");
  });

  $("#sendToDecrypt").addEventListener("click", () => {
    if (!State.lastPackage) return;
    $("#decPackage").value = JSON.stringify(State.lastPackage, null, 2);
    showView("decrypt");
    onPackageChanged();
  });

  selectAlgorithm(State.algorithm);
}

function selectAlgorithm(id) {
  State.algorithm = id;
  $$("#algoGrid .algo-card").forEach((card) => {
    card.setAttribute("aria-pressed", String(card.dataset.algo === id));
  });

  const meta = State.algorithms.find((a) => a.id === id) || {};
  $("#algoHint").textContent = meta.key_hint || "";

  const isClassical = CLASSICAL.has(id);
  $("#classicalKey").classList.toggle("hidden", !isClassical);
  $("#symmetricKey").classList.toggle("hidden", id !== "aes");
  $("#publicKeyBlock").classList.toggle("hidden", !PUBLIC_KEY.has(id));

  const caesar = id === "caesar";
  $("#caesarSlider").classList.toggle("hidden", !caesar);
  $("#encKey").classList.toggle("hidden", caesar);
  $("#encKeyLabel").textContent = caesar ? "Shift" : "Keyword";
  $("#keyHint").textContent = {
    caesar: "Only 25 possible keys - drag the slider and watch the wheel.",
    vigenere: "Letters only. A longer keyword resists analysis a little longer.",
    playfair: "The keyword fills the 5x5 square; I and J share a cell.",
  }[id] || "";

  if (!caesar && isClassical && !$("#encKey").value) {
    $("#encKey").value = id === "playfair" ? "MONARCHY" : "LEMON";
  }

  $("#encVizPanel").hidden = !isClassical;
  updateStatus();
  refreshAudit();
  refreshPreview();
}

function updateStatus() {
  const label = {
    aes: `aes-${$("#encBits").value}-${$("#encMode").value}`,
    rsa: "rsa-2048-oaep",
    hybrid: "rsa+aes-256-gcm",
  }[State.algorithm] || State.algorithm;
  status("ready", label);
}

const refreshAudit = debounce(async () => {
  try {
    const audit = await API.audit({
      algorithm: State.algorithm,
      secret: State.keySource === "raw" ? "" : $("#encSecret").value,
      secret_kind: State.keySource === "raw" ? "password" : State.keySource,
      message: $("#encMessage").value,
      mode: State.algorithm === "aes" ? $("#encMode").value : null,
      key_bits: State.algorithm === "aes" ? Number($("#encBits").value) : null,
    });
    State.lastAudit = audit;
    Viz.meter(audit);
  } catch (error) {
    /* the meter is advisory - a failed refresh should not interrupt anything */
  }
}, 240);

const refreshPreview = debounce(async () => {
  if (!CLASSICAL.has(State.algorithm)) return;
  const message = $("#encMessage").value || "HELLO WORLD";
  const key = State.algorithm === "caesar" ? $("#encShift").value : $("#encKey").value;
  if (State.algorithm !== "caesar" && !key) return;
  try {
    const data = await API.preview({
      algorithm: State.algorithm, message, key,
    });
    renderClassicalViz(data, message, key);
  } catch (error) {
    $("#encViz").innerHTML = `<p class="hint">${escapeHtml(error.message)}</p>`;
  }
}, 220);

function renderClassicalViz(data, message, key) {
  const host = $("#encViz");
  const letters = message.replace(/[^a-zA-Z]/g, "").toUpperCase().slice(0, 6);

  if (State.algorithm === "caesar") {
    const shift = Number(key) || 3;
    host.innerHTML =
      Viz.caesarWheel(shift) +
      Viz.mappingStrip(shift, letters) +
      `<p class="inline-note">Outer ring is the plaintext alphabet, inner dial is the ciphertext alphabet rotated by ${shift}.</p>`;
    return;
  }

  if (State.algorithm === "vigenere") {
    const first = letters[0];
    const keyLetter = (data.keystream || "").replace(/\s/g, "")[0] || "A";
    const row = ALPHABET.indexOf(keyLetter);
    const col = ALPHABET.indexOf(first || "A");
    const table = State.tabula || [];
    host.innerHTML = `
      <div><span class="label">Keystream</span>
        <pre class="out" style="max-height:110px">${escapeHtml(message.slice(0, 60))}\n${escapeHtml((data.keystream || "").slice(0, 60))}</pre>
      </div>
      ${table.length ? Viz.tabulaRecta(table, row, col) : ""}
      <p class="inline-note">Row ${keyLetter} (key) crossed with column ${first || "?"} (plaintext) gives the ciphertext letter.</p>`;
    return;
  }

  const square = data.explain && data.explain.square;
  const hits = (data.explain && data.explain.steps && data.explain.steps[0])
    ? data.explain.steps[0].cells : [];
  host.innerHTML = `
    ${square ? Viz.playfairSquare(square, hits) : ""}
    <p class="inline-note">First pair: <span class="accent">${escapeHtml((data.explain?.digraphs || [])[0] || "")}</span>
      &rarr; <span class="accent">${escapeHtml((data.explain?.steps || [])[0]?.result || "")}</span>
      (${escapeHtml((data.explain?.steps || [])[0]?.rule || "")})</p>`;
}

async function doEncrypt() {
  const message = $("#encMessage").value;
  if (!message) {
    toast("There is no message to encrypt.", "err");
    $("#encMessage").focus();
    return;
  }

  const body = {
    algorithm: State.algorithm,
    message,
    sender: $("#encSender").value,
    recipient: $("#encRecipient").value,
    explain: true,
    iv_history: State.ivHistory,
  };

  if (State.algorithm === "caesar") {
    body.key = $("#encShift").value;
  } else if (CLASSICAL.has(State.algorithm)) {
    body.key = $("#encKey").value;
  } else if (State.algorithm === "aes") {
    if (State.keySource === "raw") body.key = $("#encSecret").value;
    else {
      body.secret = $("#encSecret").value;
      body.secret_kind = State.keySource;
    }
    body.kdf = $("#encKdf").value;
    body.aes_mode = $("#encMode").value;
    body.key_bits = Number($("#encBits").value);
  } else {
    body.public_pem = $("#encPublicPem").value;
  }

  await withBusy($("#encryptBtn"), async () => {
    try {
      const result = await API.encrypt(body);
      State.lastPackage = result.package;
      if (result.package.params && result.package.params.iv) {
        State.ivHistory.push(result.package.params.iv);
      }

      $("#resultPanel").hidden = false;
      $("#encOut").textContent = result.ciphertext;
      $("#encPkg").innerHTML = Viz.json(result.package);
      $("#pkgSize").textContent = `${result.package_json.length} bytes`;

      Viz.meter(result.audit);

      $("#encExplainPanel").hidden = !result.explanation;
      if (result.explanation) Viz.explanation(result.explanation, $("#encExplain"));

      status("encrypted");
      toast(`Encrypted with ${result.algorithm.toUpperCase()}`, "ok");
      $("#resultPanel").scrollIntoView({ behavior: "smooth", block: "nearest" });
    } catch (error) {
      toast(error.message, "err");
      status("error");
    }
  });
}

/* ==========================================================================
   Decrypt
   ========================================================================== */

function initDecrypt() {
  $("#decPackage").addEventListener("input", debounce(onPackageChanged, 250));

  const drop = $("#pkgDrop");
  const file = $("#pkgFile");
  drop.addEventListener("click", () => file.click());
  file.addEventListener("change", () => {
    if (file.files[0]) readPackageFile(file.files[0]);
  });
  ["dragenter", "dragover"].forEach((name) => {
    drop.addEventListener(name, (event) => {
      event.preventDefault();
      drop.classList.add("over");
    });
  });
  ["dragleave", "drop"].forEach((name) => {
    drop.addEventListener(name, (event) => {
      event.preventDefault();
      drop.classList.remove("over");
      if (name === "drop" && event.dataTransfer.files[0]) {
        readPackageFile(event.dataTransfer.files[0]);
      }
    });
  });

  $("#revealDecSecret").addEventListener("click", () => {
    const input = $("#decSecret");
    const hidden = input.type === "password";
    input.type = hidden ? "text" : "password";
    $("#revealDecSecret").textContent = hidden ? "hide" : "show";
  });

  $("#useMyPrivate").addEventListener("click", () => {
    if (!State.rsaPair) {
      toast("Generate an RSA pair on the Keys tab first.", "err");
      showView("keys");
      return;
    }
    $("#decPrivatePem").value = State.rsaPair.private_pem;
    toast("Private key filled in");
  });

  $("#decryptBtn").addEventListener("click", doDecrypt);
  $("#inspectBtn").addEventListener("click", doInspect);
}

function readPackageFile(file) {
  const reader = new FileReader();
  reader.onload = () => {
    $("#decPackage").value = String(reader.result);
    onPackageChanged();
    toast(`Loaded ${file.name}`, "ok");
  };
  reader.onerror = () => toast("Could not read that file.", "err");
  reader.readAsText(file);
}

function parsePackageField() {
  const text = $("#decPackage").value.trim();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;   // present but unparseable
  }
}

function onPackageChanged() {
  const pkg = parsePackageField();
  const statusLine = $("#pkgStatus");

  if (pkg === null) {
    statusLine.textContent = "";
    return;
  }
  if (pkg === undefined) {
    statusLine.textContent = "That is not valid JSON yet.";
    return;
  }

  const algorithm = (pkg.algorithm || "").toLowerCase();
  statusLine.innerHTML = `Recognised <span class="accent">${escapeHtml(algorithm || "?")}</span> package from ${escapeHtml(pkg.sender || "anonymous")}.`;

  $("#decSecretField").classList.toggle("hidden", algorithm !== "aes");
  $("#decKeyField").classList.toggle("hidden", !["vigenere", "playfair"].includes(algorithm));
  $("#decPrivateField").classList.toggle("hidden", !PUBLIC_KEY.has(algorithm));
}

function decryptBody() {
  const pkg = parsePackageField();
  if (pkg === null) throw new Error("Paste or drop a package first.");
  if (pkg === undefined) throw new Error("The package is not valid JSON.");
  return {
    package: pkg,
    secret: $("#decSecret").value,
    key: $("#decKey").value,
    private_pem: $("#decPrivatePem").value,
    verify_public_pem: $("#decVerify").value,
    explain: true,
  };
}

async function doInspect() {
  await withBusy($("#inspectBtn"), async () => {
    try {
      const body = decryptBody();
      const { describe } = await API.inspect(body.package);
      renderPackageInfo(describe);
      toast("Package inspected - nothing was decrypted");
    } catch (error) {
      toast(error.message, "err");
    }
  });
}

function renderPackageInfo(info) {
  $("#pkgInfoPanel").hidden = false;
  const rows = [
    ["algorithm", info.algorithm],
    ["created", info.created],
    ["from", info.sender],
    ["to", info.recipient],
    ["ciphertext", `${info.ciphertext_chars} chars`],
    ["carries", info.carries.join(", ")],
    ["never carries", info.never_carries.join(", ")],
    ["you need", info.you_need.join(", ")],
    ["checksum", info.checksum_ok ? "matches" : "MISMATCH"],
    ["authenticated", info.authenticated ? "yes (GCM tag)" : "no"],
    ["signed", info.signed ? "yes" : "no"],
  ];
  if (info.note) rows.push(["note", info.note]);

  $("#pkgInfo").innerHTML = rows.map(([key, value]) => {
    const bad = value === "MISMATCH";
    return `<dt>${escapeHtml(key)}</dt><dd class="${bad ? "v-unsafe" : ""}">${escapeHtml(String(value))}</dd>`;
  }).join("");
}

async function doDecrypt() {
  await withBusy($("#decryptBtn"), async () => {
    try {
      const result = await API.decrypt(decryptBody());
      renderPackageInfo(result.describe);

      $("#plainPanel").hidden = false;
      $("#decOut").textContent = result.plaintext;

      const notices = $("#decNotices");
      notices.innerHTML = "";
      if (result.authenticated) {
        notices.append(el("p", {
          class: "inline-note",
          text: "The authentication tag verified - this message was not altered in transit.",
        }));
      }
      if (result.signature) {
        const valid = result.signature.valid;
        notices.append(el("p", {
          class: valid === true ? "accent" : valid === false ? "v-unsafe" : "inline-note",
          text: result.signature.message,
        }));
      }
      if (result.notices && result.notices.length) {
        const list = el("ul", { class: "findings" });
        Viz.findings(result.notices, list);
        notices.append(list);
      }

      $("#decExplainPanel").hidden = !result.explanation;
      if (result.explanation) Viz.explanation(result.explanation, $("#decExplain"));

      status("decrypted");
      toast("Decrypted", "ok");
    } catch (error) {
      toast(error.message, "err");
      status("decryption failed");
    }
  });
}

/* ==========================================================================
   Keys
   ========================================================================== */

function initKeys() {
  $("#genAesBtn").addEventListener("click", async () => {
    await withBusy($("#genAesBtn"), async () => {
      try {
        const result = await API.keys({
          kind: "aes", key_bits: Number($("#aesKeyBits").value),
        });
        $("#aesKeyOut").innerHTML =
          `<span class="muted">key      </span> ${escapeHtml(result.key_b64)}\n` +
          `<span class="muted">bits     </span> ${result.bits}\n` +
          `<span class="muted">source   </span> ${escapeHtml(result.source)}\n` +
          `<span class="muted">sha-256  </span> ${escapeHtml(result.fingerprint)}`;
        toast("Key generated", "ok");
      } catch (error) {
        toast(error.message, "err");
      }
    });
  });

  $("#genRsaBtn").addEventListener("click", async () => {
    const bits = Number($("#rsaBits").value);
    if (bits >= 4096) toast("4096-bit generation takes a few seconds...");
    await withBusy($("#genRsaBtn"), async () => {
      try {
        const result = await API.keys({
          kind: "rsa", bits, passphrase: $("#rsaPass").value,
        });
        State.rsaPair = result;
        const host = $("#rsaOut");
        host.innerHTML = "";
        host.append(
          el("dl", {
            class: "kv",
            html: `<dt>size</dt><dd>RSA-${result.bits}</dd>
                   <dt>fingerprint</dt><dd class="accent">${escapeHtml(result.fingerprint)}</dd>
                   <dt>direct limit</dt><dd>${result.max_plaintext_bytes} bytes per block</dd>
                   <dt>private key</dt><dd>${result.protected ? "passphrase-protected" : "unprotected"}</dd>`,
          }),
          el("div", { class: "label", text: "Public key - share this" }),
          el("div", { class: "copy-wrap" }, [
            el("button", {
              class: "btn tiny ghost",
              onclick: (event) => copyText(result.public_pem, event.target),
              text: "copy",
            }),
            el("pre", { class: "out", text: result.public_pem }),
          ]),
          el("div", { class: "label", text: "Private key - keep this" }),
          el("div", { class: "copy-wrap" }, [
            el("button", {
              class: "btn tiny ghost",
              onclick: (event) => copyText(result.private_pem, event.target),
              text: "copy",
            }),
            el("pre", { class: "out", text: result.private_pem }),
          ]),
        );
        const findingsList = el("ul", { class: "findings" });
        Viz.findings(result.audit.findings, findingsList);
        host.append(findingsList);
        toast(`RSA-${result.bits} pair generated`, "ok");
      } catch (error) {
        toast(error.message, "err");
      }
    });
  });

  $("#genDerBtn").addEventListener("click", async () => {
    await withBusy($("#genDerBtn"), async () => {
      try {
        const result = await API.keys({
          kind: "derive",
          secret: $("#derSecret").value,
          secret_kind: $("#derKind").value,
          kdf: $("#derKdf").value,
        });
        const host = $("#derOut");
        host.innerHTML = "";
        host.append(el("dl", {
          class: "kv",
          html: `<dt>kdf</dt><dd>${escapeHtml(result.kdf)}</dd>
                 <dt>parameters</dt><dd>${escapeHtml(JSON.stringify(result.params))}</dd>
                 <dt>salt</dt><dd>${escapeHtml(result.salt_b64)}</dd>
                 <dt>key length</dt><dd>${result.length} bytes</dd>
                 <dt>fingerprint</dt><dd class="accent">${escapeHtml(result.fingerprint)}</dd>`,
        }));
        host.append(el("p", { class: "inline-note", text: result.explain.summary }));
        host.append(el("p", { class: "inline-note", text: result.explain.why_not_raw }));
        const findingsList = el("ul", { class: "findings" });
        Viz.findings(result.audit.findings, findingsList);
        host.append(findingsList);
        toast("Key derived - the key itself stays on the server", "ok");
      } catch (error) {
        toast(error.message, "err");
      }
    });
  });

  $("#dhToyBtn").addEventListener("click", () => runExchange("toy", $("#dhToyBtn")));
  $("#dhRealBtn").addEventListener("click", () => runExchange("real", $("#dhRealBtn")));
}

async function runExchange(mode, button) {
  await withBusy(button, async () => {
    try {
      const result = await API.exchange(mode);
      const host = $("#dhOut");
      host.innerHTML = "";
      if (mode === "toy") {
        const list = el("ol", { class: "steps" });
        result.steps.forEach((step, index) => {
          const item = el("li", { html: `<div>${escapeHtml(step)}</div>` });
          item.style.animationDelay = `${index * 160}ms`;
          list.append(item);
        });
        host.append(list);
        host.append(el("p", {
          class: result.agreed ? "accent" : "v-unsafe",
          text: result.agreed
            ? `Both sides computed ${result.alice_shared}. It never crossed the wire.`
            : "The two sides disagreed, which should never happen.",
        }));
        host.append(el("p", { class: "inline-note", text: result.warning }));
      } else {
        host.append(el("dl", {
          class: "kv",
          html: `<dt>group</dt><dd>${escapeHtml(result.group)}</dd>
                 <dt>prime size</dt><dd>${result.prime_bits} bits</dd>
                 <dt>raw secret</dt><dd>${result.raw_secret_bytes} bytes</dd>
                 <dt>session key</dt><dd class="accent">${escapeHtml(result.session_key_b64)}</dd>
                 <dt>agreed</dt><dd>${result.agreed ? "yes" : "no"}</dd>`,
        }));
        host.append(el("p", { class: "inline-note", text: result.note }));
      }
      toast("Exchange complete", "ok");
    } catch (error) {
      toast(error.message, "err");
    }
  });
}

/* ==========================================================================
   Agent
   ========================================================================== */

const SUGGESTIONS = [
  'Encrypt "meet me at dawn" and send it securely to Bob using RSA',
  "Encrypt my note with a caesar shift of 7",
  "Generate a 4096-bit key pair",
  "Break this caesar ciphertext",
  "Explain how AES works step by step",
  "Agree on a shared secret with Diffie-Hellman",
];

function initAgent() {
  const host = $("#suggestions");
  SUGGESTIONS.forEach((text) => {
    host.append(el("button", {
      class: "chip",
      text: text.length > 42 ? `${text.slice(0, 40)}...` : text,
      title: text,
      type: "button",
      onclick: () => {
        $("#agentInput").value = text;
        askAgent();
      },
    }));
  });

  addBubble("bot", `<div class="who">pico</div>Tell me what you want to do and I will lay out the plan before anything runs. Try one of the suggestions below.`);

  $("#agentSend").addEventListener("click", askAgent);
  $("#agentInput").addEventListener("keydown", (event) => {
    if (event.key === "Enter") askAgent();
  });
}

function addBubble(who, html) {
  const bubble = el("div", { class: `bubble ${who}`, html });
  $("#chat").append(bubble);
  $("#chat").scrollTop = $("#chat").scrollHeight;
  return bubble;
}

async function askAgent() {
  const input = $("#agentInput");
  const text = input.value.trim();
  if (!text) return;

  addBubble("me", `<div class="who">you</div>${escapeHtml(text)}`);
  input.value = "";

  const thinking = addBubble("bot",
    `<div class="who">pico</div><div class="typing"><span></span><span></span><span></span></div>`);

  try {
    const plan = await API.agent(text);
    await new Promise((resolve) => setTimeout(resolve, 320));
    thinking.remove();

    if (!plan.ok) {
      addBubble("bot", `<div class="who">pico</div>${escapeHtml(plan.reply)}`);
      return;
    }

    const steps = plan.plan.map((step) => `<li>${escapeHtml(step)}</li>`).join("");
    const missing = plan.missing && plan.missing.length
      ? `<div class="missing">Still needed: ${escapeHtml(plan.missing.join(", "))}</div>` : "";

    addBubble("bot", `
      <div class="who">pico</div>
      ${escapeHtml(plan.reply)}
      <ol class="plan">${steps}</ol>
      ${missing}
      <div class="meta">
        <span>intent: ${escapeHtml(plan.intent)}</span>
        <span>confidence: ${Math.round(plan.confidence * 100)}%</span>
        <span>route: ${escapeHtml(plan.route)}</span>
      </div>`);

    renderAgentPlan(plan);
  } catch (error) {
    thinking.remove();
    addBubble("bot", `<div class="who">pico</div><span class="v-unsafe">${escapeHtml(error.message)}</span>`);
  }
}

function renderAgentPlan(plan) {
  const host = $("#agentPlan");
  host.innerHTML = "";

  host.append(el("dl", {
    class: "kv",
    html: `<dt>intent</dt><dd class="accent">${escapeHtml(plan.intent)}</dd>
           <dt>algorithm</dt><dd>${escapeHtml(plan.algorithm)}</dd>
           <dt>confidence</dt><dd>${Math.round(plan.confidence * 100)}%</dd>
           <dt>routes to</dt><dd>${escapeHtml(plan.route)}</dd>`,
  }));

  if (plan.notes && plan.notes.length) {
    const list = el("ul", { class: "findings" });
    plan.notes.forEach((note) => {
      list.append(el("li", { class: "finding info", html: `<p>${escapeHtml(note)}</p>` }));
    });
    host.append(list);
  }

  const params = Object.entries(plan.params || {})
    .filter(([key]) => key !== "algorithm");
  if (params.length) {
    host.append(el("div", { class: "label", text: "Parameters picked up" }));
    host.append(el("pre", {
      class: "out",
      html: Viz.json(Object.fromEntries(params)),
    }));
  }

  host.append(el("div", { class: "row actions", style: "margin-top:14px" }, [
    el("button", {
      class: "btn primary",
      text: "Set this up ›",
      onclick: () => applyAgentPlan(plan),
    }),
  ]));

  host.append(el("p", { class: "inline-note", text: plan.disclaimer }));
}

function applyAgentPlan(plan) {
  const params = plan.params || {};

  if (plan.intent === "encrypt") {
    showView("encrypt");
    selectAlgorithm(params.algorithm || "aes");
    if (params.message) {
      $("#encMessage").value = params.message;
      $("#encCount").textContent = `${params.message.length} chars`;
    }
    if (params.recipient) $("#encRecipient").value = params.recipient;
    if (params.key && CLASSICAL.has(State.algorithm)) {
      if (State.algorithm === "caesar") {
        $("#encShift").value = params.key;
        $("#shiftValue").textContent = params.key;
      } else {
        $("#encKey").value = params.key;
      }
    }
    if (params.secret && State.algorithm === "aes") $("#encSecret").value = params.secret;
    if (params.aes_mode) $("#encMode").value = params.aes_mode;
    if (params.key_bits) $("#encBits").value = String(params.key_bits);
    refreshAudit();
    refreshPreview();
    toast("Encrypt tab filled in - review it, then run it", "ok");
    return;
  }

  if (plan.intent === "decrypt") {
    showView("decrypt");
    toast("Paste the package you received");
    return;
  }
  if (plan.intent === "generate") {
    showView("keys");
    if (params.bits) $("#rsaBits").value = String(params.bits);
    toast("Keys tab ready");
    return;
  }
  if (plan.intent === "analyse") {
    showView("break");
    setBreakAlgorithm(params.algorithm === "vigenere" ? "vigenere" : "caesar");
    if (params.message) $("#breakText").value = params.message;
    toast("Break tab ready - paste the intercept");
    return;
  }
  if (plan.intent === "explain") {
    showView("learn");
    setLearnTopic(["caesar", "vigenere", "playfair", "aes", "rsa", "dh"]
      .includes(params.algorithm) ? params.algorithm : "aes");
    return;
  }
  showView("keys");
  runExchange("toy", $("#dhToyBtn"));
}

/* ==========================================================================
   Learn
   ========================================================================== */

function initLearn() {
  $("#learnChips").addEventListener("click", (event) => {
    const chip = event.target.closest(".chip");
    if (chip) setLearnTopic(chip.dataset.topic);
  });
  setLearnTopic("caesar");
}

async function setLearnTopic(topic) {
  State.learnTopic = topic;
  $$("#learnChips .chip").forEach((chip) => {
    chip.setAttribute("aria-pressed", String(chip.dataset.topic === topic));
  });

  const titles = {
    caesar: "Caesar", vigenere: "Vigenere", playfair: "Playfair", aes: "AES",
    rsa: "RSA", dh: "Diffie-Hellman", kdf: "Key derivation",
  };
  $("#learnTitle").innerHTML = `<span class="idx">&gt;</span> ${titles[topic]}`;

  try {
    const data = await API.explain({ algorithm: topic });
    Viz.explanation(data, $("#learnBody"));
  } catch (error) {
    $("#learnBody").innerHTML = `<p class="hint">${escapeHtml(error.message)}</p>`;
  }
  renderLearnViz(topic);
}

async function renderLearnViz(topic) {
  const host = $("#learnViz");
  host.innerHTML = "";

  if (topic === "caesar") {
    host.innerHTML = `
      <label class="label" for="learnShift">Shift <span class="accent" id="learnShiftValue">3</span></label>
      <input type="range" id="learnShift" min="0" max="25" value="3" style="width:100%">
      <div id="learnWheel"></div>
      <div class="field"><label for="learnCaesarText">Try a word</label>
        <input type="text" id="learnCaesarText" value="HELLO" autocomplete="off"></div>
      <pre class="out" id="learnCaesarOut"></pre>`;

    const update = () => {
      const shift = Number($("#learnShift").value);
      const text = $("#learnCaesarText").value;
      $("#learnShiftValue").textContent = shift;
      $("#learnWheel").innerHTML = Viz.caesarWheel(shift) +
        Viz.mappingStrip(shift, text.replace(/[^a-z]/gi, ""));
      const out = text.replace(/[a-z]/gi, (ch) => {
        const base = ch === ch.toUpperCase() ? 65 : 97;
        return String.fromCharCode(((ch.charCodeAt(0) - base + shift) % 26) + base);
      });
      $("#learnCaesarOut").textContent = `${text}\n${out}`;
    };
    $("#learnShift").addEventListener("input", update);
    $("#learnCaesarText").addEventListener("input", update);
    update();
    return;
  }

  if (topic === "vigenere") {
    const table = State.tabula || (await API.tabula()).table;
    State.tabula = table;
    host.innerHTML = `
      <div class="row">
        <div class="field" style="margin:0"><label for="learnVigKey">Keyword</label>
          <input type="text" id="learnVigKey" value="LEMON" autocomplete="off"></div>
        <div class="field" style="margin:0"><label for="learnVigText">Message</label>
          <input type="text" id="learnVigText" value="ATTACK AT DAWN" autocomplete="off"></div>
      </div>
      <pre class="out" id="learnVigOut"></pre>
      <div id="learnTabula"></div>
      <p class="inline-note">The highlighted cell is where the first plaintext letter meets its key letter.</p>`;

    const update = debounce(async () => {
      const key = $("#learnVigKey").value || "A";
      const message = $("#learnVigText").value;
      try {
        const data = await API.preview({ algorithm: "vigenere", message, key });
        $("#learnVigOut").textContent =
          `plain  ${message}\nkey    ${data.keystream}\ncipher ${data.ciphertext}`;
        const firstLetter = (message.match(/[a-z]/i) || ["A"])[0].toUpperCase();
        const firstKey = (data.keystream.match(/[A-Z]/) || ["A"])[0];
        $("#learnTabula").innerHTML = Viz.tabulaRecta(
          table, ALPHABET.indexOf(firstKey), ALPHABET.indexOf(firstLetter));
      } catch (error) {
        $("#learnVigOut").textContent = error.message;
      }
    }, 220);

    $("#learnVigKey").addEventListener("input", update);
    $("#learnVigText").addEventListener("input", update);
    update();
    return;
  }

  if (topic === "playfair") {
    host.innerHTML = `
      <div class="field"><label for="learnPfKey">Keyword</label>
        <input type="text" id="learnPfKey" value="MONARCHY" autocomplete="off"></div>
      <div id="learnSquare"></div>
      <div class="field" style="margin-top:12px"><label for="learnPfText">Message</label>
        <input type="text" id="learnPfText" value="HIDE THE GOLD" autocomplete="off"></div>
      <pre class="out" id="learnPfOut"></pre>`;

    const update = debounce(async () => {
      const key = $("#learnPfKey").value || "MONARCHY";
      const message = $("#learnPfText").value;
      try {
        const [squareData, preview] = await Promise.all([
          API.square(key),
          API.preview({ algorithm: "playfair", message, key }),
        ]);
        const first = (preview.explain.steps || [])[0];
        $("#learnSquare").innerHTML = Viz.playfairSquare(
          squareData.square, first ? first.cells : []);
        const pairs = (preview.explain.digraphs || []).join(" ");
        $("#learnPfOut").textContent =
          `pairs  ${pairs}\ncipher ${preview.ciphertext}` +
          (first ? `\nfirst  ${first.pair} -> ${first.result}  (${first.rule})` : "");
      } catch (error) {
        $("#learnPfOut").textContent = error.message;
      }
    }, 220);

    $("#learnPfKey").addEventListener("input", update);
    $("#learnPfText").addEventListener("input", update);
    update();
    return;
  }

  if (topic === "aes") {
    host.innerHTML = `
      <p class="hint">A 16-byte block as a 4x4 state. Step through one round.</p>
      <div class="round-list" id="roundList"></div>
      <div style="display:grid;place-items:center;margin:14px 0">${Viz.aesState("pico")}</div>
      <p class="inline-note" id="roundNote">SubBytes replaces every byte using the S-box.</p>`;

    const rounds = [
      ["SubBytes", "Every byte is replaced through the S-box lookup table. This is the confusion step."],
      ["ShiftRows", "Rows 1, 2 and 3 of the state rotate left by 1, 2 and 3 bytes."],
      ["MixColumns", "Each column is multiplied by a fixed matrix in GF(2^8). This is the diffusion step, and it is skipped in the final round."],
      ["AddRoundKey", "The state is XORed with this round's key from the key schedule."],
    ];
    const list = $("#roundList");
    rounds.forEach(([name, note], index) => {
      list.append(el("button", {
        type: "button",
        text: name,
        "aria-pressed": String(index === 0),
        onclick: (event) => {
          $$("#roundList button").forEach((button) => button.setAttribute("aria-pressed", "false"));
          event.target.setAttribute("aria-pressed", "true");
          $("#roundNote").textContent = note;
          Viz.shuffleState(host);
        },
      }));
    });
    return;
  }

  if (topic === "rsa") {
    host.innerHTML = `
      <p class="hint">RSA with small primes, so the arithmetic fits on screen. Real keys use 1024-bit primes.</p>
      <div class="row">
        <div class="field" style="margin:0"><label for="rsaP">p (prime)</label>
          <input type="number" id="rsaP" value="61" min="3" max="997"></div>
        <div class="field" style="margin:0"><label for="rsaQ">q (prime)</label>
          <input type="number" id="rsaQ" value="53" min="3" max="997"></div>
        <div class="field" style="margin:0"><label for="rsaE">e</label>
          <input type="number" id="rsaE" value="17" min="3"></div>
      </div>
      <div class="field"><label for="rsaM">Message as a number (m &lt; n)</label>
        <input type="number" id="rsaM" value="65" min="0"></div>
      <pre class="out" id="rsaToyOut"></pre>`;

    const update = () => {
      const p = Number($("#rsaP").value);
      const q = Number($("#rsaQ").value);
      const e = Number($("#rsaE").value);
      const m = Number($("#rsaM").value);
      $("#rsaToyOut").textContent = toyRsa(p, q, e, m);
    };
    ["#rsaP", "#rsaQ", "#rsaE", "#rsaM"].forEach((id) => {
      $(id).addEventListener("input", debounce(update, 200));
    });
    update();
    return;
  }

  if (topic === "dh") {
    host.innerHTML = `
      <p class="hint">Run the exchange and watch the shared secret appear on both sides without ever being sent.</p>
      <div class="row actions">
        <button class="btn" id="learnDhToy">Small numbers</button>
        <button class="btn ghost" id="learnDhReal">Real 2048-bit</button>
      </div>
      <div id="learnDhOut" style="margin-top:12px"></div>`;

    const render = async (mode, button) => {
      await withBusy(button, async () => {
        const result = await API.exchange(mode);
        const out = $("#learnDhOut");
        out.innerHTML = "";
        if (mode === "toy") {
          const list = el("ol", { class: "steps" });
          result.steps.forEach((step, index) => {
            const item = el("li", { html: `<div>${escapeHtml(step)}</div>` });
            item.style.animationDelay = `${index * 150}ms`;
            list.append(item);
          });
          out.append(list, el("p", { class: "inline-note", text: result.warning }));
        } else {
          out.append(el("dl", {
            class: "kv",
            html: `<dt>prime</dt><dd>${result.prime_bits} bits</dd>
                   <dt>session key</dt><dd class="accent">${escapeHtml(result.session_key_b64)}</dd>
                   <dt>agreed</dt><dd>${result.agreed ? "yes" : "no"}</dd>`,
          }), el("p", { class: "inline-note", text: result.note }));
        }
      });
    };
    $("#learnDhToy").addEventListener("click", (event) => render("toy", event.target));
    $("#learnDhReal").addEventListener("click", (event) => render("real", event.target));
    render("toy", $("#learnDhToy"));
    return;
  }

  /* kdf */
  host.innerHTML = `
    <p class="hint">Watch the same password produce a different key every time, because the salt changes.</p>
    <div class="field"><label for="kdfSecret">Secret</label>
      <input type="text" id="kdfSecret" value="tuesday-blue-42" autocomplete="off"></div>
    <div class="field"><label for="kdfPick">KDF</label>
      <select id="kdfPick">
        <option value="pbkdf2">PBKDF2-SHA256</option>
        <option value="scrypt">scrypt</option>
        <option value="hkdf">HKDF-SHA256</option>
      </select></div>
    <button class="btn primary" id="kdfRun">Derive once</button>
    <div id="kdfRuns" class="stack" style="margin-top:12px"></div>`;

  $("#kdfRun").addEventListener("click", async (event) => {
    await withBusy(event.target, async () => {
      try {
        const result = await API.keys({
          kind: "derive",
          secret: $("#kdfSecret").value,
          kdf: $("#kdfPick").value,
        });
        $("#kdfRuns").prepend(el("dl", {
          class: "kv",
          html: `<dt>salt</dt><dd>${escapeHtml(result.salt_b64)}</dd>
                 <dt>key fingerprint</dt><dd class="accent">${escapeHtml(result.fingerprint)}</dd>`,
        }));
      } catch (error) {
        toast(error.message, "err");
      }
    });
  });
}

/* A deliberately tiny RSA, for the Learn tab only. */
function toyRsa(p, q, e, m) {
  const isPrime = (n) => {
    if (n < 2) return false;
    for (let i = 2; i * i <= n; i += 1) if (n % i === 0) return false;
    return true;
  };
  const gcd = (a, b) => (b ? gcd(b, a % b) : a);
  const modPow = (base, exponent, modulus) => {
    let result = 1n;
    let b = BigInt(base) % BigInt(modulus);
    let e2 = BigInt(exponent);
    const mod = BigInt(modulus);
    while (e2 > 0n) {
      if (e2 & 1n) result = (result * b) % mod;
      b = (b * b) % mod;
      e2 >>= 1n;
    }
    return result;
  };

  if (!isPrime(p) || !isPrime(q)) return "p and q must both be prime.";
  if (p === q) return "p and q must be different primes.";
  const n = p * q;
  const phi = (p - 1) * (q - 1);
  if (e <= 1 || e >= phi) return `e must sit between 2 and phi(n) = ${phi}.`;
  if (gcd(e, phi) !== 1) return `e = ${e} shares a factor with phi(n) = ${phi}. Pick another e.`;
  if (m >= n) return `The message must be smaller than n = ${n}.`;

  let d = 1;
  while ((d * e) % phi !== 1) {
    d += 1;
    if (d > phi) return "No inverse found.";
  }

  const c = modPow(m, e, n);
  const back = modPow(c, d, n);
  return [
    `n     = p * q = ${p} * ${q} = ${n}`,
    `phi   = (p-1)(q-1) = ${phi}`,
    `public  key = (n=${n}, e=${e})`,
    `private key = (n=${n}, d=${d})     because ${e} * ${d} mod ${phi} = 1`,
    "",
    `encrypt: c = m^e mod n = ${m}^${e} mod ${n} = ${c}`,
    `decrypt: m = c^d mod n = ${c}^${d} mod ${n} = ${back}`,
    back === BigInt(m) ? "recovered the original message" : "mismatch",
  ].join("\n");
}

/* ==========================================================================
   Break
   ========================================================================== */

function initBreak() {
  $("#breakChips").addEventListener("click", (event) => {
    const chip = event.target.closest(".chip");
    if (chip) setBreakAlgorithm(chip.dataset.algo);
  });

  $("#breakSample").addEventListener("click", () => {
    // Real ciphertexts, produced by PICO itself, so the attacks actually land.
    const samples = {
      // Caesar, shift 11
      caesar: "Xppe xp mj esp zwo mctorp le xtoytrse. Mctyr esp xla lyo epww yz zyp.",
      // Vigenere, key CIPHER - long enough for the statistics to work
      vigenere: "vpt prugf dm gfkvrphvpkt aicna jz lfy npy e tkxwlvkgfi zmku ngvq "
        + "icvsvq kgfi hru vppa wzpoal rlojty mj gvdbky vw glgfxmg alv nmcnxy qn "
        + "ioi bgg pmxvt ewpgy gdtyc tqtjtr tqtahtjga xuxf cv dyhzpigf grgapy wykni",
      // AES-256-GCM - nothing to attack, which is the lesson
      aes: "YW2JOWvBrDbU9Y8SA2W1EVgG4UmfvAr0QhE6kK2f8pM=",
    };
    $("#breakText").value = samples[State.breakAlgorithm] || samples.caesar;
    toast("Intercept loaded");
  });

  $("#breakBtn").addEventListener("click", doBreak);
}

function setBreakAlgorithm(algorithm) {
  State.breakAlgorithm = algorithm;
  $$("#breakChips .chip").forEach((chip) => {
    chip.setAttribute("aria-pressed", String(chip.dataset.algo === algorithm));
  });
}

async function doBreak() {
  const ciphertext = $("#breakText").value.trim();
  if (!ciphertext) {
    toast("Paste a ciphertext first.", "err");
    return;
  }

  await withBusy($("#breakBtn"), async () => {
    try {
      const result = await API.analyse({
        ciphertext, algorithm: State.breakAlgorithm,
      });
      const host = $("#breakResult");
      $("#breakResultPanel").hidden = false;
      host.innerHTML = "";

      host.append(el("dl", {
        class: "kv",
        html: `<dt>attack</dt><dd>${escapeHtml(result.attack)}</dd>
               <dt>target</dt><dd>${escapeHtml(result.target)}</dd>
               ${result.effort ? `<dt>effort</dt><dd>${escapeHtml(result.effort)}</dd>` : ""}
               ${result.key_space ? `<dt>key space</dt><dd>${escapeHtml(result.key_space)}</dd>` : ""}`,
      }));

      if (result.error) {
        host.append(el("p", { class: "v-unsafe", text: result.error }));
        return;
      }

      if (State.breakAlgorithm === "caesar") {
        $("#freqPanel").hidden = false;
        Viz.histogram(result.frequencies, $("#histogram"));
        host.append(el("div", { class: "label", text: "All 25 keys, ranked" }));
        const list = el("div", { class: "candidates" });
        Viz.candidates(result.candidates, list, (row) => {
          copyText(row.plaintext);
          toast(`Copied the shift ${row.shift} decryption`);
        });
        host.append(list);
      } else if (State.breakAlgorithm === "vigenere") {
        $("#freqPanel").hidden = true;
        host.append(el("dl", {
          class: "kv",
          html: `<dt>index of coincidence</dt><dd>${result.ciphertext_ic}
                   <span class="muted">(English ${result.english_ic}, random ${result.random_ic})</span></dd>
                 <dt>key length</dt><dd>${result.key_lengths.slice(0, 4)
                   .map((row) => `${row.length} (ic ${row.ic})`).join(", ")}</dd>
                 <dt>recovered key</dt><dd class="accent">${escapeHtml(result.recovered_key)}</dd>`,
        }));
        host.append(el("div", { class: "label", text: "Recovered plaintext" }));
        host.append(el("pre", { class: "out plain", text: result.recovered_plaintext }));
        if (result.kasiski && result.kasiski.length) {
          host.append(el("div", { class: "label", text: "Kasiski: repeated sequences" }));
          host.append(el("pre", {
            class: "out",
            text: result.kasiski.slice(0, 5)
              .map((row) => `${row.sequence}  at ${row.positions.join(", ")}  gaps ${row.gaps.join(", ")}`)
              .join("\n"),
          }));
        }
      } else {
        $("#freqPanel").hidden = true;
        const list = el("ul", { class: "findings" });
        (result.what_breaks_instead || []).forEach((item) => {
          list.append(el("li", { class: "finding warning", html: `<p>${escapeHtml(item)}</p>` }));
        });
        host.append(el("div", { class: "label", text: "What actually breaks AES deployments" }), list);
      }

      host.append(el("p", { class: "accent", text: result.verdict }));
      host.append(el("p", { class: "inline-note", text: result.lesson }));
      status("analysis complete");
      toast("Attack finished", "ok");
    } catch (error) {
      toast(error.message, "err");
    }
  });
}

/* ==========================================================================
   Start
   ========================================================================== */

async function main() {
  runBoot();
  initChrome();
  Globe.init();
  if (STORE.get("pico.globe", "1") !== "1") Globe.stop();

  initDecrypt();
  initKeys();
  initAgent();
  initBreak();
  initLearn();

  try {
    const health = await API.health();
    $("#statusVersion").textContent = health.version;
  } catch (error) {
    toast(error.message, "err");
  }

  try {
    await initEncrypt();
    State.tabula = (await API.tabula()).table;
  } catch (error) {
    toast(`Could not load the algorithm list: ${error.message}`, "err");
  }
}

document.addEventListener("DOMContentLoaded", main);
