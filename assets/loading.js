// The script of armada's page while the web app downloads (loading.html).
// It draws the sea, asks /_armada/status.json how far the download has got,
// and reloads into the app once it's live.
"use strict";

// The ASCII sea, from the app's landing page (AsciiSea.tsx), without the
// scrolling: cyan swell and rose crests, redrawn from three summed sines.
(function sea() {
  var host = document.getElementById("sea");
  if (!host) return;

  var SWELL_RAMP = "  ..,,--~~";
  var CREST_GLYPH = "\u2248";
  var CREST_THRESHOLD = 0.88;
  var FPS = 14;
  // Rows above the mask's transparent band aren't drawn.
  var HIDDEN_ABOVE = 0.62;

  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var swellLayer = document.createElement("div");
  var crestLayer = document.createElement("div");
  [swellLayer, crestLayer].forEach(function (layer) {
    layer.style.cssText = "position:absolute;inset:0;";
    host.appendChild(layer);
  });

  // The cell box, in the sea's own font.
  var probe = document.createElement("div");
  probe.textContent = "0";
  probe.style.cssText = "position:absolute;visibility:hidden;white-space:pre;top:0;left:0;";
  host.appendChild(probe);

  var swellRows = [];
  var crestRows = [];
  var cols = 0;
  var rowCount = 0;

  function build() {
    var cell = probe.getBoundingClientRect();
    var cw = cell.width || 8;
    var ch = cell.height || 14;
    var nextCols = Math.max(8, Math.ceil(host.clientWidth / cw) + 2);
    var nextRows = Math.max(4, Math.ceil(host.clientHeight / ch));
    if (nextCols === cols && nextRows === rowCount) return;
    cols = nextCols;
    rowCount = nextRows;

    swellLayer.replaceChildren();
    crestLayer.replaceChildren();
    swellRows = [];
    crestRows = [];
    for (var y = 0; y < rowCount; y++) {
      var near = y / Math.max(rowCount - 1, 1);
      // Empty rows keep their height, or the band collapses upward.
      var swell = document.createElement("div");
      swell.style.height = "1em";
      swell.style.color = "hsl(var(--accent2) / " + (0.07 + 0.3 * near).toFixed(3) + ")";
      swellLayer.appendChild(swell);
      swellRows.push(swell);
      var crest = document.createElement("div");
      crest.style.height = "1em";
      crest.style.color = "hsl(var(--primary) / " + (0.05 + 0.4 * near).toFixed(3) + ")";
      crestLayer.appendChild(crest);
      crestRows.push(crest);
    }
  }

  function paint(phase) {
    var from = Math.max(0, Math.floor(HIDDEN_ABOVE * rowCount) - 3);
    for (var y = from; y < rowCount; y++) {
      var near = y / Math.max(rowCount - 1, 1);
      var amp = 0.32 + 0.68 * near;
      var freq = 0.3 - 0.2 * near;
      var swell = "";
      var crest = "";
      for (var x = 0; x < cols; x++) {
        // Incommensurate sines, so the surface never repeats; the y terms
        // shear the rows into one surface.
        var h =
          Math.sin(x * freq + phase * 0.9 + y * 0.55) +
          0.6 * Math.sin(x * freq * 2.3 - phase * 1.35 + y * 0.29) +
          0.4 * Math.sin(x * freq * 0.45 + phase * 0.5 - y * 0.17);
        var n = 0.5 + (h / 2) * amp * 0.5;
        if (n > CREST_THRESHOLD) {
          crest += CREST_GLYPH;
          swell += " ";
        } else {
          crest += " ";
          swell += SWELL_RAMP[Math.round(n * (SWELL_RAMP.length - 1))];
        }
      }
      swellRows[y].textContent = swell;
      crestRows[y].textContent = crest;
    }
  }

  var start = performance.now();
  function remeasure() {
    build();
    paint(reduced ? 0 : (performance.now() - start) / 1000);
  }
  new ResizeObserver(remeasure).observe(host);
  // A font swapping in changes the cell without resizing the host.
  if (document.fonts) document.fonts.ready.then(remeasure, function () {});
  remeasure();
  if (reduced) return;

  [swellLayer, crestLayer].forEach(function (layer) {
    layer.style.willChange = "transform";
  });
  // At the paint cadence, not every frame, and not at all while hidden.
  var timer;
  function schedule() {
    if (timer !== undefined || document.hidden) return;
    timer = setTimeout(function () {
      timer = undefined;
      requestAnimationFrame(function (now) {
        paint((now - start) / 1000);
        schedule();
      });
    }, 1000 / FPS);
  }
  document.addEventListener("visibilitychange", schedule);
  schedule();
})();

// How far the download has got, until the app is live.
(function status() {
  var text = document.getElementById("status");
  var bar = document.getElementById("bar");
  var fill = document.getElementById("fill");
  var POLL = 2000;
  var POLL_MAX = 15000;
  var wait = POLL;

  function show(line, fraction) {
    text.textContent = line;
    bar.classList.toggle("shown", fraction !== undefined);
    if (fraction !== undefined) fill.style.width = (Math.min(1, fraction) * 100).toFixed(1) + "%";
  }

  function render(status) {
    switch (status.state) {
      case "searching":
        return show("looking for armada on relays");
      case "not_found":
        return show("no relay has armada yet; trying again soon");
      case "downloading":
        return show(
          "downloading \u00b7 " + status.done + " of " + status.total + " files",
          status.total ? status.done / status.total : 0
        );
      case "failed":
        return show("download failed; retrying");
      case "live":
        show("ready", 1);
        // A moment to see it full, then the app.
        setTimeout(function () { location.reload(); }, 400);
        return true;
    }
  }

  function poll() {
    fetch("/_armada/status.json", { cache: "no-store" })
      .then(function (response) {
        if (!response.ok) throw new Error(response.status);
        return response.json();
      })
      .then(function (status) {
        wait = POLL;
        if (render(status) !== true) setTimeout(poll, wait);
      })
      .catch(function () {
        // The server may be restarting: keep asking, less often.
        wait = Math.min(wait * 2, POLL_MAX);
        setTimeout(poll, wait);
      });
  }
  poll();
})();
