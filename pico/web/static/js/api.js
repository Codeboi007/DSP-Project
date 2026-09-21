/* Thin wrapper around the PICO HTTP API. Every call returns parsed JSON and
   throws an Error carrying the server's own message, so callers can just
   try/catch and show it. */

const API = (() => {
  async function request(path, body, method = "POST") {
    let response;
    try {
      response = await fetch(path, {
        method,
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch (networkError) {
      throw new Error("Could not reach the PICO backend. Is the server running?");
    }

    let data = null;
    const text = await response.text();
    if (text) {
      try {
        data = JSON.parse(text);
      } catch (parseError) {
        throw new Error("The server returned something that is not JSON.");
      }
    }

    if (!response.ok) {
      const detail = data && (data.detail || data.error);
      throw new Error(detail || `Request failed (${response.status}).`);
    }
    return data;
  }

  const get = (path) => request(path, null, "GET");

  return {
    health: () => get("/api/health"),
    algorithms: () => get("/api/algorithms"),
    encrypt: (body) => request("/api/encrypt", body),
    decrypt: (body) => request("/api/decrypt", body),
    keys: (body) => request("/api/keys", body),
    audit: (body) => request("/api/audit", body),
    analyse: (body) => request("/api/analyse", body),
    agent: (text) => request("/api/agent", { request: text }),
    explain: (body) => request("/api/explain", body),
    exchange: (mode) => request("/api/exchange", { mode }),
    inspect: (pkg) => request("/api/package/inspect", { package: pkg }),
    preview: (body) => request("/api/preview", body),
    tabula: () => get("/api/visual/vigenere"),
    square: (key) => get(`/api/visual/playfair?key=${encodeURIComponent(key)}`),
  };
})();
