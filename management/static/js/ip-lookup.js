/* IP lookup popovers for the audit and log pages.
   ================================================
   A manager reading an address in the log wants to know who it is without
   leaving the page. This widget turns any element carrying `data-ip` into a
   control that opens a small panel with the ip66.dev view of that address:
   country, continent, autonomous system and the anonymising flags.

   Three things it deliberately is not:

   * **Not a hover-only affordance.** Hover opens it for a mouse, but the element
     is a real button, so keyboard (Enter/Space) and touch reach the same panel.
     A feature that only exists under a cursor does not exist.
   * **Not a second copy of the data.** The panel is built from the lookup
     response and thrown away when it closes; the row keeps the country
     Cloudflare reported, and a disagreement between the two is shown as such
     rather than resolved.
   * **Not chatty.** Responses are cached in localStorage for a few hours, so
     reading the same address twice costs one request, not two.

   The endpoint is `/manage/ip`, which is behind the manage session - the panel
   is the only thing that can ask, and a lapsed session answers with a 401 that
   this widget reports as "session expired" instead of an empty panel. */
(function () {
  "use strict";

  var ENDPOINT = "/manage/ip";
  var CACHE_KEY = "gk.ipgeo.cache.v1";
  var TTL_MS = 3 * 60 * 60 * 1000;
  var HOVER_DELAY_MS = 160;

  var cache = readCache();
  var pop = null;
  var current = null;
  var hoverTimer = null;

  function readCache() {
    try { return JSON.parse(localStorage.getItem(CACHE_KEY)) || {}; } catch (e) { return {}; }
  }

  function saveCache() {
    try { localStorage.setItem(CACHE_KEY, JSON.stringify(cache)); } catch (e) { /* private mode, quota: live without it */ }
  }

  function cached(ip) {
    var hit = cache[ip];
    if (!hit) return null;
    if (Date.now() - hit.at > TTL_MS) { delete cache[ip]; saveCache(); return null; }
    return hit.data;
  }

  function fetchLookup(ip, country) {
    var hit = cached(ip);
    if (hit) return Promise.resolve(hit);
    var url = ENDPOINT + "?ip=" + encodeURIComponent(ip);
    if (country) url += "&country=" + encodeURIComponent(country);
    return fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" })
      .then(function (res) {
        if (res.status === 401) throw new Error("Session expired - reload to sign in again.");
        if (!res.ok) throw new Error("Lookup failed (" + res.status + ").");
        return res.json();
      })
      .then(function (data) { cache[ip] = { at: Date.now(), data: data }; saveCache(); return data; });
  }

  function style() {
    if (document.getElementById("ipgeo-style")) return;
    var css = document.createElement("style");
    css.id = "ipgeo-style";
    css.textContent =
      ".ipgeo-trigger{font:inherit;font-family:inherit;color:inherit;background:none;border:0;padding:0;cursor:help;" +
      "border-bottom:1px dotted currentColor;text-align:left}" +
      ".ipgeo-trigger:hover,.ipgeo-trigger:focus-visible{color:var(--accent);outline:none}" +
      ".ipgeo-trigger:focus-visible{box-shadow:0 0 0 2px var(--accent-dim);border-radius:3px}" +
      ".ipgeo-pop{position:fixed;z-index:2000;width:min(320px,calc(100vw - 2rem));background:var(--bg-card);" +
      "border:1px solid var(--border);border-radius:10px;box-shadow:0 12px 32px rgba(0,0,0,.45);" +
      "color:var(--text-primary);font-size:.82rem;line-height:1.45;padding:.7rem .8rem}" +
      ".ipgeo-pop[hidden]{display:none}" +
      ".ipgeo-head{display:flex;align-items:center;justify-content:space-between;gap:.5rem;margin-bottom:.45rem;" +
      "font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--text-secondary)}" +
      ".ipgeo-close{background:none;border:0;color:var(--text-secondary);cursor:pointer;font-size:1rem;line-height:1;padding:0 .1rem}" +
      ".ipgeo-close:hover{color:var(--text-primary)}" +
      ".ipgeo-row{display:flex;justify-content:space-between;gap:.75rem}" +
      ".ipgeo-row .k{color:var(--text-secondary)}" +
      ".ipgeo-row .v{text-align:right;font-family:'JetBrains Mono',monospace}" +
      ".ipgeo-flags{display:flex;flex-wrap:wrap;gap:.3rem;margin-top:.5rem}" +
      ".ipgeo-flag{background:rgba(248,113,113,.15);color:#f87171;border:1px solid rgba(248,113,113,.35);" +
      "border-radius:999px;padding:1px 7px;font-size:.68rem;font-family:'JetBrains Mono',monospace;letter-spacing:.02em}" +
      ".ipgeo-warn{margin-top:.5rem;background:rgba(251,191,36,.12);border:1px solid rgba(251,191,36,.35);" +
      "border-radius:6px;padding:.4rem .55rem;color:#fbbf24;font-size:.75rem}" +
      ".ipgeo-muted{color:var(--text-secondary)}";
    document.head.appendChild(css);
  }

  function ensurePop() {
    if (pop) return pop;
    pop = document.createElement("div");
    pop.className = "ipgeo-pop";
    pop.setAttribute("role", "dialog");
    pop.setAttribute("aria-label", "IP details");
    pop.hidden = true;
    document.body.appendChild(pop);
    pop.addEventListener("click", function (ev) {
      if (ev.target.closest(".ipgeo-close")) hide();
    });
    document.addEventListener("keydown", function (ev) { if (ev.key === "Escape") hide(); });
    document.addEventListener("click", function (ev) {
      if (!pop.hidden && !pop.contains(ev.target) && !ev.target.closest(".ipgeo-trigger")) hide();
    });
    window.addEventListener("resize", hide);
    document.addEventListener("scroll", hide, true);
    return pop;
  }

  function placement(anchor) {
    var box = anchor.getBoundingClientRect();
    pop.style.left = "0px"; pop.style.top = "0px"; pop.hidden = false;
    var w = pop.offsetWidth, h = pop.offsetHeight;
    var left = Math.min(Math.max(8, box.left), window.innerWidth - w - 8);
    var top = box.bottom + 6;
    if (top + h > window.innerHeight - 8) top = Math.max(8, box.top - h - 6);
    pop.style.left = left + "px";
    pop.style.top = top + "px";
  }

  function row(label, value) {
    return '<div class="ipgeo-row"><span class="k">' + label + '</span><span class="v">' + value + "</span></div>";
  }

  function esc(text) {
    return String(text == null ? "" : text).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function render(ip, data) {
    var lookup = data.lookup || {};
    var country = lookup.country || {};
    var continent = lookup.continent || {};
    var asn = lookup.asn || {};
    var html = '<div class="ipgeo-head"><span>' + esc(ip) + "</span>" +
      '<button type="button" class="ipgeo-close" aria-label="Close">&times;</button></div>';

    if (!data.found) {
      html += '<div class="ipgeo-muted">This address is not in the ip66 database, or the database is not available right now.</div>';
    } else {
      html += row("Country", esc(country.name || " - ") + (country.code ? " (" + esc(country.code) + ")" : ""));
      html += row("Continent", esc(continent.name || " - "));
      if (asn.number) {
        html += row("AS", "AS" + esc(asn.number));
      }
      if (asn.organization) {
        html += row("Operator", esc(asn.organization));
      }
      var flags = lookup.flags || [];
      if (flags.length) {
        html += '<div class="ipgeo-flags">' + flags.map(function (f) {
          return '<span class="ipgeo-flag">' + esc(f) + "</span>";
        }).join("") + "</div>";
      }
      if (data.mismatch) {
        html += '<div class="ipgeo-warn">Red flag: Cloudflare reported a different country than the database resolves for this address.</div>';
      }
    }
    pop.innerHTML = html;
  }

  function show(anchor) {
    /* The button deliberately carries no `data-ip` of its own: `decorate` wraps
       the cell's text, and putting the address on the button would make the
       MutationObserver decorate the button again on its next pass. So read the
       address from the cell the button sits in. */
    var holder = anchor.closest("[data-ip]") || anchor;
    var ip = holder.getAttribute("data-ip");
    if (!ip) return;
    ensurePop();
    current = anchor;
    pop.innerHTML = '<div class="ipgeo-head"><span>' + esc(ip) + '</span></div><div class="ipgeo-muted">Looking up&hellip;</div>';
    placement(anchor);
    fetchLookup(ip, holder.getAttribute("data-country"))
      .then(function (data) { if (current === anchor) { render(ip, data); placement(anchor); } })
      .catch(function (err) {
        if (current !== anchor) return;
        pop.innerHTML = '<div class="ipgeo-head"><span>' + esc(ip) + '</span>' +
          '<button type="button" class="ipgeo-close" aria-label="Close">&times;</button></div>' +
          '<div class="ipgeo-muted">' + esc(err.message || "Lookup failed.") + "</div>";
      });
  }

  function hide() {
    if (pop) pop.hidden = true;
    current = null;
  }

  function decorate(el) {
    if (el.dataset.ipgeoReady === "1" || !el.getAttribute("data-ip")) return;
    el.dataset.ipgeoReady = "1";
    var raw = el.textContent;
    el.textContent = "";
    var button = document.createElement("button");
    button.type = "button";
    button.className = "ipgeo-trigger";
    button.setAttribute("aria-haspopup", "dialog");
    button.setAttribute("aria-label", "IP details for " + raw.trim());
    button.textContent = raw.trim();
    button.addEventListener("click", function (ev) { ev.stopPropagation(); show(button); });
    button.addEventListener("mouseenter", function () {
      hoverTimer = setTimeout(function () { show(button); }, HOVER_DELAY_MS);
    });
    button.addEventListener("mouseleave", function () {
      clearTimeout(hoverTimer);
    });
    el.appendChild(button);
  }

  function scan(root) {
    var scope = root || document;
    var nodes = scope.querySelectorAll("[data-ip]");
    for (var i = 0; i < nodes.length; i++) decorate(nodes[i]);
    if (scope.nodeType === 1 && scope.matches && scope.matches("[data-ip]")) decorate(scope);
  }

  function start() {
    style();
    scan(document);
    /* The log table is rebuilt per page of results by the page's own script, so
       new address cells appear after load. Watching is cheaper than making every
       caller remember to re-run this. */
    var observer = new MutationObserver(function (records) {
      for (var i = 0; i < records.length; i++) {
        var added = records[i].addedNodes;
        for (var j = 0; j < added.length; j++) {
          if (added[j].nodeType === 1) scan(added[j]);
        }
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
