/* OpenTrustBench site.js — vanilla, no dependencies. */
(function () {
  "use strict";
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ── Theme toggle ──────────────────────────────────── */
  (function initTheme() {
    var root = document.documentElement;
    var saved = null;
    try { saved = localStorage.getItem("theme"); } catch (_) {}

    if (saved === "light" || saved === "dark") {
      root.setAttribute("data-theme", saved);
    }
    // else: no attribute, CSS media query handles system default

    function getEffective() {
      if (root.hasAttribute("data-theme")) return root.getAttribute("data-theme");
      return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }

    function updateIcons() {
      var btn = document.querySelector(".theme-toggle");
      if (!btn) return;
      var dark = getEffective() === "dark";
      btn.setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
    }
    updateIcons();

    // Listen for system preference changes (only when no manual override)
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () {
      if (!root.hasAttribute("data-theme")) updateIcons();
    });

    document.addEventListener("click", function (e) {
      var btn = e.target.closest(".theme-toggle");
      if (!btn) return;
      var current = getEffective();
      var next = current === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("theme", next); } catch (_) {}
      updateIcons();
    });
  })();

  /* ── Nav state + mobile menu ───────────────────────── */
  var nav = document.querySelector(".nav");
  var onScroll = function () { if (nav) nav.classList.toggle("scrolled", window.scrollY > 8); };
  window.addEventListener("scroll", onScroll, { passive: true }); onScroll();
  var burger = document.querySelector(".burger");
  var links = document.querySelector(".nav-links");
  if (burger && links) {
    burger.addEventListener("click", function () {
      var open = links.classList.toggle("open");
      burger.setAttribute("aria-expanded", open ? "true" : "false");
    });
    links.addEventListener("click", function (e) {
      if (e.target.tagName === "A") { links.classList.remove("open"); burger.setAttribute("aria-expanded", "false"); }
    });
  }

  /* ── Copy buttons ──────────────────────────────────── */
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-copy],[data-copy-target]");
    if (!btn) return;
    var text = btn.getAttribute("data-copy") ||
      (document.querySelector(btn.getAttribute("data-copy-target")) || {}).textContent || "";
    text = text.trim();
    if (!text) return;
    var done = function () {
      var orig = btn.innerHTML;
      btn.innerHTML = "Copied";
      setTimeout(function () { btn.innerHTML = orig; }, 1600);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, done);
    } else {
      var ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); } catch (_) {}
      document.body.removeChild(ta); done();
    }
  });

  /* ── Install tabs ──────────────────────────────────── */
  document.querySelectorAll('[role="tablist"]').forEach(function (list) {
    var tabs = Array.prototype.slice.call(list.querySelectorAll('[role="tab"]'));
    var scope = list.parentElement;
    var select = function (tab, focus) {
      tabs.forEach(function (t) {
        var on = t === tab;
        t.setAttribute("aria-selected", on ? "true" : "false");
        t.tabIndex = on ? 0 : -1;
        if (focus && on) t.focus();
      });
      scope.querySelectorAll('[role="tabpanel"]').forEach(function (p) {
        p.hidden = p.getAttribute("data-panel") !== tab.getAttribute("data-tab");
      });
    };
    tabs.forEach(function (tab, i) {
      tab.addEventListener("click", function () { select(tab, false); });
      tab.addEventListener("keydown", function (e) {
        var j = null;
        if (e.key === "ArrowRight") j = (i + 1) % tabs.length;
        else if (e.key === "ArrowLeft") j = (i - 1 + tabs.length) % tabs.length;
        else if (e.key === "Home") j = 0;
        else if (e.key === "End") j = tabs.length - 1;
        if (j !== null) { e.preventDefault(); select(tabs[j], true); }
      });
    });
  });

  /* ── Scroll reveals ────────────────────────────────── */
  var revealEls = document.querySelectorAll(".reveal");
  if (reduced || !("IntersectionObserver" in window)) {
    revealEls.forEach(function (el) { el.classList.add("in"); });
  } else {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); }
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -6% 0px" });
    revealEls.forEach(function (el) { io.observe(el); });
  }

  /* ── Hero terminal typing ──────────────────────────── */
  var term = document.getElementById("term");
  if (term) {
    var full = term.getAttribute("data-lines") || "";
    var body = term.querySelector(".term-body");
    var render = function (upto, showCaret) {
      var html = upto
        .replace(/&/g, "&amp;").replace(/</g, "&lt;")
        .replace(/\[G\](.*?)\[\/G\]/g, '<span class="tok-g">$1</span>')
        .replace(/\[C\](.*?)\[\/C\]/g, '<span class="tok-c">$1</span>')
        .replace(/\[D\](.*?)\[\/D\]/g, '<span class="tok-d">$1</span>');
      body.innerHTML = html + (showCaret ? '<span class="caret"></span>' : "");
    };
    if (reduced) { render(full, false); return; }
    var started = false;
    var tObserver = new IntersectionObserver(function (entries) {
      if (!entries[0].isIntersecting || started) return;
      started = true; tObserver.disconnect();
      var i = 0;
      var tick = function () {
        i += 1 + Math.floor(Math.random() * 3);
        if (i >= full.length) { render(full, false); return; }
        render(full.slice(0, i), true);
        setTimeout(tick, 14);
      };
      setTimeout(tick, 500);
    }, { threshold: 0.35 });
    tObserver.observe(term);
  }

  /* ── Registry explorer ─────────────────────────────── */
  var table = document.getElementById("registry-table");
  if (table) {
    var dataEl = document.getElementById("registry-data");
    var rows = JSON.parse(dataEl.textContent);
    var tbody = table.querySelector("tbody");
    var state = { grade: "all", q: "", sort: "score-desc" };
    var gradeClass = { A: "gA", B: "gB", C: "gC", D: "gD", F: "gF", U: "gU" };

    var hist = document.getElementById("grade-hist");
    if (hist) {
      var counts = { A: 0, B: 0, C: 0, D: 0, F: 0 };
      rows.forEach(function (r) { counts[r.grade] = (counts[r.grade] || 0) + 1; });
      var max = Math.max.apply(null, Object.values(counts).concat([1]));
      var colors = { A: "#34d399", B: "#22d3ee", C: "#fbbf24", D: "#fb923c", F: "#fb7185" };
      hist.innerHTML = ["A", "B", "C", "D", "F"].map(function (g) {
        var h = Math.max(4, Math.round((counts[g] / max) * 68));
        return '<div style="height:' + h + 'px;background:' + colors[g] + '" title="' + g + ': ' + counts[g] + '"></div>';
      }).join("");
    }

    var render = function () {
      var list = rows.filter(function (r) {
        if (state.grade !== "all" && r.grade !== state.grade) return false;
        if (state.q && (r.title + " " + r.scope).toLowerCase().indexOf(state.q) < 0) return false;
        return true;
      });
      var rank = { A: 0, B: 1, C: 2, D: 3, F: 4 };
      list.sort(function (a, b) {
        if (state.sort === "score-desc") return b.overall - a.overall;
        if (state.sort === "score-asc") return a.overall - b.overall;
        if (state.sort === "findings-desc") return b.total - a.total;
        return (rank[a.grade] - rank[b.grade]) || (b.overall - a.overall);
      });
      tbody.innerHTML = list.map(function (r) {
        return "<tr><td><span class=\"grade " + (gradeClass[r.grade] || "") + "\">" + r.grade +
          "</span></td><td><a href=\"" + r.url + "\">" + r.title.replace(/&/g, "&amp;").replace(/</g, "&lt;") +
          "</a></td><td>" + r.overall + "</td><td>" + r.total + " (" + r.crit + " crit)</td><td>" + r.scope +
          '</td><td><a href="' + r.url + '"><img src="' + r.badge + '" alt="OpenTrustBench ' + r.grade + '" loading="lazy"></a></td></tr>';
      }).join("");
      document.getElementById("registry-count").textContent =
        "Showing " + list.length + " of " + rows.length + " scanned servers";
    };

    document.querySelectorAll(".chip[data-grade]").forEach(function (chip) {
      chip.addEventListener("click", function () {
        state.grade = chip.getAttribute("data-grade");
        document.querySelectorAll(".chip[data-grade]").forEach(function (c) {
          c.setAttribute("aria-pressed", c === chip ? "true" : "false");
        });
        render();
      });
    });
    var search = document.getElementById("registry-search");
    if (search) search.addEventListener("input", function () { state.q = search.value.trim().toLowerCase(); render(); });
    var sort = document.getElementById("registry-sort");
    if (sort) sort.addEventListener("change", function () { state.sort = sort.value; render(); });
    render();
  }
})();
