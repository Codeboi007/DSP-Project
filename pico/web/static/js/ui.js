/* Shared UI plumbing: DOM helpers, themes, toasts, the boot sequence and the
   tab router. Nothing here knows anything about cryptography. */

const $ = (selector, scope = document) => scope.querySelector(selector);
const $$ = (selector, scope = document) => Array.from(scope.querySelectorAll(selector));

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  Object.entries(attrs).forEach(([name, value]) => {
    if (value === null || value === undefined || value === false) return;
    if (name === "class") node.className = value;
    else if (name === "text") node.textContent = value;
    else if (name === "html") node.innerHTML = value;
    else if (name.startsWith("on") && typeof value === "function") {
      node.addEventListener(name.slice(2).toLowerCase(), value);
    } else node.setAttribute(name, value === true ? "" : value);
  });
  (Array.isArray(children) ? children : [children])
    .filter(Boolean)
    .forEach((child) => node.append(child));
  return node;
}

const escapeHtml = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[ch]);

/* Not every environment implements matchMedia, so ask defensively. */
const prefersReducedMotion = () =>
  typeof window.matchMedia === "function" &&
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function debounce(fn, wait = 260) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), wait);
  };
}

/* ---------- toasts ------------------------------------------------------- */

function toast(message, kind = "") {
  const host = $("#toasts");
  const node = el("div", { class: `toast ${kind}`, text: message });
  host.append(node);
  setTimeout(() => {
    node.classList.add("out");
    setTimeout(() => node.remove(), 260);
  }, kind === "err" ? 5200 : 3200);
  return node;
}

function status(text, algorithm) {
  $("#statusText").textContent = text;
  if (algorithm) $("#statusAlgo").textContent = algorithm;
}

/* ---------- busy state --------------------------------------------------- */

async function withBusy(button, task) {
  button.classList.add("is-busy");
  button.disabled = true;
  try {
    return await task();
  } finally {
    button.classList.remove("is-busy");
    button.disabled = false;
  }
}

/* ---------- themes ------------------------------------------------------- */

const THEMES = ["www", "phosphor", "amber", "synth", "matrix", "blueprint", "paper"];
const STORE = {
  get(key, fallback) {
    try { return localStorage.getItem(key) ?? fallback; } catch { return fallback; }
  },
  set(key, value) {
    try { localStorage.setItem(key, value); } catch { /* private mode */ }
  },
};

function applyTheme(name) {
  const theme = THEMES.includes(name) ? name : "www";
  document.documentElement.dataset.theme = theme;
  $$("#swatches .swatch").forEach((swatch) => {
    swatch.setAttribute("aria-pressed", String(swatch.dataset.theme === theme));
  });
  STORE.set("pico.theme", theme);
  document.dispatchEvent(new CustomEvent("pico:theme", { detail: theme }));
}

function nextTheme() {
  const current = document.documentElement.dataset.theme || "www";
  applyTheme(THEMES[(THEMES.indexOf(current) + 1) % THEMES.length]);
  toast(`Theme: ${document.documentElement.dataset.theme}`);
}

function setToggle(button, on, key) {
  button.setAttribute("aria-pressed", String(on));
  button.style.opacity = on ? "1" : "0.45";
  if (key) STORE.set(key, on ? "1" : "0");
}

/* ---------- tabs --------------------------------------------------------- */

function showView(name) {
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `view-${name}`));
  $$("#tabs .tab").forEach((tab) => {
    tab.setAttribute("aria-selected", String(tab.dataset.view === name));
  });
  STORE.set("pico.view", name);
  document.dispatchEvent(new CustomEvent("pico:view", { detail: name }));
}

const currentView = () =>
  ($(".view.active") || {}).id?.replace("view-", "") || "encrypt";

/* ---------- copy --------------------------------------------------------- */

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const helper = el("textarea", { style: "position:fixed;opacity:0" });
    helper.value = text;
    document.body.append(helper);
    helper.select();
    try { document.execCommand("copy"); } catch { /* nothing else to try */ }
    helper.remove();
  }
  if (button) {
    const original = button.textContent;
    button.textContent = "copied";
    setTimeout(() => { button.textContent = original; }, 1200);
  }
}

/* ---------- boot sequence ------------------------------------------------ */

function runBoot() {
  const boot = $("#boot");
  const lines = $("#bootLines");
  const bar = $("#bootBar");
  const script = [
    "PICO bootstrap v1.0.0",
    "checking entropy source .......... [ ok ]",
    "loading cipher modules ........... [ ok ]",
    "  caesar  playfair  vigenere",
    "  aes     rsa       diffie-hellman",
    "arming security advisor .......... [ ok ]",
    "",
    "welcome to the world wide web",
  ];

  let index = 0;
  let finished = false;

  const finish = () => {
    if (finished) return;
    finished = true;
    boot.classList.add("done");
    setTimeout(() => boot.remove(), 600);
  };

  const step = () => {
    if (finished) return;
    if (index >= script.length) {
      setTimeout(finish, 340);
      return;
    }
    const line = script[index++];
    const html = line.replace("[ ok ]", '<span class="ok">[ ok ]</span>');
    lines.innerHTML += `${html}\n`;
    bar.style.width = `${Math.round((index / script.length) * 100)}%`;
    setTimeout(step, line ? 130 : 60);
  };

  if (prefersReducedMotion()) {
    finish();
    return;
  }
  setTimeout(step, 160);
  boot.addEventListener("click", finish);
  window.addEventListener("keydown", finish, { once: true });
  setTimeout(finish, 4200);
}
