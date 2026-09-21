/* The wireframe globe behind everything: a sphere of 1s and 0s, drawn as
   characters whose brightness falls off with depth. It reads its colour from
   the active theme's --globe token, so a theme swap repaints it. */

const Globe = (() => {
  const canvas = document.getElementById("globe-canvas");
  const ctx = canvas.getContext("2d");

  let width = 0;
  let height = 0;
  let dpr = 1;
  let points = [];
  let rings = [];
  let angle = 0;
  let colour = "#1e9bff";
  let running = true;
  let frame = null;
  const reduced = prefersReducedMotion();

  /* Build the sphere once: latitude rings, each with a ring of glyphs whose
     count shrinks towards the poles so the spacing stays even. */
  function buildSphere() {
    points = [];
    rings = [];
    const latSteps = 22;
    for (let i = 1; i < latSteps; i += 1) {
      const phi = (Math.PI * i) / latSteps;          // 0 .. PI
      const y = Math.cos(phi);
      const radius = Math.sin(phi);
      const count = Math.max(6, Math.round(46 * radius));
      const ring = [];
      for (let j = 0; j < count; j += 1) {
        const theta = (2 * Math.PI * j) / count;
        const point = {
          x: radius * Math.cos(theta),
          y,
          z: radius * Math.sin(theta),
          glyph: Math.random() > 0.5 ? "1" : "0",
          // a few glyphs flicker, like a terminal refreshing
          flicker: Math.random() > 0.94,
        };
        points.push(point);
        ring.push(point);
      }
      if (i % 3 === 0) rings.push(ring);
    }
  }

  function readColour() {
    const styles = getComputedStyle(document.documentElement);
    colour = (styles.getPropertyValue("--globe") || "#1e9bff").trim();
  }

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function rgba(hex, alpha) {
    const value = hex.replace("#", "");
    const full = value.length === 3
      ? value.split("").map((c) => c + c).join("")
      : value;
    const int = parseInt(full, 16);
    if (Number.isNaN(int)) return `rgba(30,155,255,${alpha})`;
    const r = (int >> 16) & 255;
    const g = (int >> 8) & 255;
    const b = int & 255;
    return `rgba(${r},${g},${b},${alpha})`;
  }

  function project(point, cos, sin, radius, cx, cy) {
    // rotate around the Y axis, then a gentle fixed tilt on X
    const x = point.x * cos - point.z * sin;
    const z = point.x * sin + point.z * cos;
    const tilt = 0.32;
    const y = point.y * Math.cos(tilt) - z * Math.sin(tilt);
    const depth = point.y * Math.sin(tilt) + z * Math.cos(tilt);
    // mild perspective so the front of the globe reads as nearer
    const scale = 1 / (1.9 - depth * 0.55);
    return {
      sx: cx + x * radius * scale,
      sy: cy + y * radius * scale,
      depth,
      scale,
    };
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);

    const cx = width * (width > 900 ? 0.68 : 0.5);
    const cy = height * 0.46;
    const radius = Math.min(width, height) * (width > 900 ? 0.4 : 0.34);
    const cos = Math.cos(angle);
    const sin = Math.sin(angle);

    // faint wireframe rings first, so the glyphs sit on top
    ctx.lineWidth = 1;
    rings.forEach((ring) => {
      ctx.beginPath();
      ring.forEach((point, index) => {
        const p = project(point, cos, sin, radius, cx, cy);
        if (index === 0) ctx.moveTo(p.sx, p.sy);
        else ctx.lineTo(p.sx, p.sy);
      });
      ctx.closePath();
      ctx.strokeStyle = rgba(colour, 0.07);
      ctx.stroke();
    });

    ctx.textAlign = "center";
    ctx.textBaseline = "middle";

    for (let i = 0; i < points.length; i += 1) {
      const point = points[i];
      const p = project(point, cos, sin, radius, cx, cy);
      if (p.depth < -0.86) continue;           // hide the far pole clutter
      const alpha = Math.max(0.05, (p.depth + 1) / 2) * 0.62;
      const size = 7 + p.scale * 6;
      ctx.font = `${size.toFixed(1)}px "JetBrains Mono", monospace`;
      ctx.fillStyle = rgba(colour, alpha);
      if (point.flicker && Math.random() > 0.9) {
        point.glyph = point.glyph === "1" ? "0" : "1";
      }
      ctx.fillText(point.glyph, p.sx, p.sy);
    }
  }

  function loop() {
    if (!running) return;
    angle += reduced ? 0 : 0.0016;
    draw();
    frame = requestAnimationFrame(loop);
  }

  function start() {
    if (running && frame) return;
    running = true;
    canvas.style.display = "";
    loop();
  }

  function stop() {
    running = false;
    if (frame) cancelAnimationFrame(frame);
    frame = null;
    ctx.clearRect(0, 0, width, height);
    canvas.style.display = "none";
  }

  function init() {
    buildSphere();
    readColour();
    resize();
    loop();

    window.addEventListener("resize", debounce(resize, 140));
    document.addEventListener("pico:theme", readColour);
    document.addEventListener("visibilitychange", () => {
      // no point animating a hidden tab
      if (document.hidden) {
        if (frame) cancelAnimationFrame(frame);
        frame = null;
      } else if (running) {
        loop();
      }
    });
  }

  return { init, start, stop, isRunning: () => running };
})();
