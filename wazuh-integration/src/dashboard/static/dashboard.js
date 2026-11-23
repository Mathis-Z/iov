/* ETSO vulnerability prioritisation dashboard. Plain JS, no dependencies:
   it runs inside an iframe in Wazuh, which may have no internet access.

   Deep links: ?host=<agent name or id>&band=<band|open|all>&iov=<level>&q=<text>&tab=<findings|hosts|map>&theme=<dark|light>
               ?open=<agent id>:<CVE> opens that finding's details.
*/
(function () {
  "use strict";

  const BANDS = ["fix_now", "fix_soon", "plan", "low", "not_affected"];
  const OPEN = ["fix_now", "fix_soon", "plan", "low"];
  const BAND_LABEL = { fix_now: "Fix now", fix_soon: "Fix soon", plan: "Plan", low: "Low", not_affected: "Not affected" };
  const URGENCY_BAND = { act_now: "fix_now", elevated: "fix_soon", moderate: "plan", low: "low", clear: "not_affected" };
  const IOV = {
    HIGH:         { glyph: "▲", label: "Preconditions present" },
    MEDIUM:       { glyph: "●", label: "Affected, preconditions unknown" },
    LOW:          { glyph: "▼", label: "Preconditions absent" },
    ABSENT:       { glyph: "✓", label: "Not affected" },
    INCONCLUSIVE: { glyph: "?", label: "Inconclusive" },
    NOT_ASSESSED: { glyph: "–", label: "No IoV yet" },
  };
  const PAGE = 50;
  const AUTO_REFRESH_MS = 5 * 60 * 1000;

  const state = {
    data: null,
    byId: new Map(),
    tab: "findings",
    filters: { q: "", host: "", band: "open", iov: "" },
    sort: { key: "rank", dir: 1 },
    limit: PAGE,
    selected: null,
  };

  const $ = (sel) => document.querySelector(sel);

  // ── Formatting ──────────────────────────────────────────────────────────
  function esc(value) {
    return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function fmtScore(n) { return n == null ? "–" : Math.round(n).toString(); }
  function fmtEpss(p) {
    if (p == null) return "–";
    if (p < 0.0001) return "<0.01%";
    return (p * 100).toFixed(p >= 0.1 ? 0 : p >= 0.01 ? 1 : 2) + "%";
  }
  function fmtPct(p) { return p == null ? "" : Math.round(p * 100) + "th pct"; }
  function relTime(iso) {
    if (!iso) return "–";
    const t = parseTime(iso);
    if (!t) return esc(iso);
    const s = (Date.now() - t.getTime()) / 1000;
    if (s < 90) return "just now";
    if (s < 3600) return Math.round(s / 60) + " min ago";
    if (s < 86400) return Math.round(s / 3600) + " h ago";
    return Math.round(s / 86400) + " d ago";
  }
  function parseTime(v) {
    if (!v) return null;
    let t = new Date(v);
    if (isNaN(t)) t = new Date(String(v).replace(" @ ", " ")); // Dashboards CSV export format
    return isNaN(t) ? null : t;
  }
  function fmtDate(v) { const t = parseTime(v); return t ? t.toLocaleDateString() : v; }
  function ageDays(iso) { const t = parseTime(iso); return t ? (Date.now() - t.getTime()) / 86400000 : null; }
  function plural(n, word) { return n + " " + word + (n === 1 ? "" : "s"); }

  function shape(band, size) {
    size = size || 10;
    const fill = `var(--band-${band})`;
    const s = `width="${size}" height="${size}" viewBox="0 0 10 10" class="shape" aria-hidden="true"`;
    switch (band) {
      case "fix_now": return `<svg ${s}><path d="M5 0.5 L9.8 9.3 H0.2 Z" fill="${fill}"/></svg>`;
      case "fix_soon": return `<svg ${s}><path d="M5 0 L10 5 L5 10 L0 5 Z" fill="${fill}"/></svg>`;
      case "plan": return `<svg ${s}><circle cx="5" cy="5" r="4.6" fill="${fill}"/></svg>`;
      case "low": return `<svg ${s}><circle cx="5" cy="5" r="3.6" fill="none" stroke="${fill}" stroke-width="2"/></svg>`;
      default: return `<svg ${s}><path d="M1 5.2 L4 8.2 L9.2 1.8" fill="none" stroke="${fill}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
    }
  }
  function bandLabel(band) { return `<span class="band-label">${shape(band)}${esc(BAND_LABEL[band])}</span>`; }
  function iovChip(f) {
    const level = f.priority.iov_level;
    const err = f.iov && f.iov.script_error;
    const info = IOV[level] || IOV.INCONCLUSIVE;
    const label = err ? "IoV check failed" : info.label;
    return `<span class="iov ${level}${err ? " err" : ""}" title="${esc(level)}"><span class="glyph" aria-hidden="true">${err ? "!" : info.glyph}</span>${esc(label)}</span>`;
  }
  function stackBar(counts, keys, cls) {
    const total = keys.reduce((a, k) => a + (counts[k] || 0), 0);
    if (!total) return `<div class="${cls}"><span style="flex:1;background:var(--surface-2)"></span></div>`;
    return `<div class="${cls}" role="img" aria-label="${esc(keys.filter((k) => counts[k]).map((k) => counts[k] + " " + BAND_LABEL[k]).join(", "))}">` +
      keys.filter((k) => counts[k]).map((k) => `<span style="flex:${counts[k]};background:var(--band-${k})" title="${esc(BAND_LABEL[k])}: ${counts[k]}"></span>`).join("") +
      `</div>`;
  }

  // ── Data ────────────────────────────────────────────────────────────────
  async function load(refresh) {
    const btn = $("#refresh-btn");
    btn.classList.add("spin");
    try {
      const resp = await fetch("api/findings" + (refresh ? "?refresh=1" : ""), { headers: { Accept: "application/json" } });
      if (!resp.ok) {
        let detail = resp.statusText;
        try { detail = (await resp.json()).detail || detail; } catch (e) { /* not JSON */ }
        throw new Error(detail);
      }
      state.data = await resp.json();
      state.byId = new Map(state.data.findings.map((f) => [f.id, f]));
      resolveHostParam();
      $("#error").hidden = true;
      $("#loading").hidden = true;
      $("#main").hidden = false;
      render();
      if (state.selected && state.byId.has(state.selected)) openFinding(state.selected, true);
    } catch (err) {
      $("#loading").hidden = true;
      if (!state.data) {
        $("#error").hidden = false;
        $("#error").innerHTML = `<h2>Could not load the findings</h2><p>${esc(err.message)}</p><button class="btn" type="button" id="retry">Try again</button>`;
        $("#retry").onclick = () => load(true);
      }
      console.error(err);
    } finally {
      btn.classList.remove("spin");
    }
  }

  // ── Rendering ───────────────────────────────────────────────────────────
  // The overview follows the host filter. The estate summary comes from the
  // server; a host's is computed here the same way (findings.summarise()).
  const URGENCY_OF_BAND = { fix_now: ["act_now", "Act now"], fix_soon: ["elevated", "Elevated"], plan: ["moderate", "Moderate"], low: ["low", "Low"] };

  function scopeHost() {
    return state.filters.host ? state.data.hosts.find((h) => h.agent_id === state.filters.host) || null : null;
  }
  function scopedFindings() {
    const host = state.filters.host;
    return host ? state.data.findings.filter((f) => f.agent_id === host) : state.data.findings;
  }
  function summary() {
    return state.filters.host ? summariseFindings(scopedFindings()) : state.data.summary;
  }
  function summariseFindings(findings) {
    const bands = Object.fromEntries(BANDS.map((b) => [b, 0]));
    const levels = {};
    for (const f of findings) {
      bands[f.priority.band.key] += 1;
      levels[f.priority.iov_level] = (levels[f.priority.iov_level] || 0) + 1;
    }
    // Findings arrive sorted by priority, so the first open one is the worst.
    const open = findings.filter((f) => OPEN.includes(f.priority.band.key));
    const worst = open[0] || null;
    const [key, label] = worst ? URGENCY_OF_BAND[worst.priority.band.key] : ["clear", "Clear"];
    const conclusive = ["HIGH", "MEDIUM", "LOW", "ABSENT"].reduce((n, l) => n + (levels[l] || 0), 0);
    const atRisk = new Set(open.filter((f) => ["fix_now", "fix_soon"].includes(f.priority.band.key)).map((f) => f.agent_id));
    return {
      total: findings.length,
      open: open.length,
      bands,
      iov_levels: levels,
      urgency: {
        key, label,
        score: worst ? worst.priority.score : 0,
        driver: worst ? { id: worst.id, cve_id: worst.cve_id, agent_name: worst.agent_name, summary: worst.priority.summary } : null,
        hosts_at_risk: atRisk.size,
      },
      iov: {
        coverage: findings.length ? conclusive / findings.length : 0,
        conclusive,
        ruled_out: levels.ABSENT || 0,
        deprioritised: levels.LOW || 0,
        confirmed: levels.HIGH || 0,
        script_error_cves: [...new Set(findings.filter((f) => f.iov && f.iov.script_error).map((f) => f.cve_id))].sort(),
      },
    };
  }

  function renderOverview() {
    $("#count-findings").textContent = summary().open;
    renderUrgency();
    renderTiles();
  }

  function render() {
    const d = state.data;
    const src = $("#source");
    src.hidden = false;
    src.classList.toggle("demo", d.source.kind === "demo");
    $("#source-label").textContent = `${d.source.label} · updated ${relTime(d.loaded_at)}`;
    src.title = d.source.detail;
    $("#count-hosts").textContent = d.hosts.length;

    renderHostOptions();
    renderOverview();
    syncFilterInputs();
    renderTab();
  }

  function renderUrgency() {
    const s = summary();
    const host = scopeHost();
    const u = s.urgency;
    const band = URGENCY_BAND[u.key];
    const el = $("#urgency");
    el.style.setProperty("--u-color", `var(--band-${band})`);
    const driver = u.driver
      ? `<p class="u-driver">Driven by <a href="#" data-open="${esc(u.driver.id)}">${esc(u.driver.cve_id)}</a> on <b>${esc(u.driver.agent_name)}</b>: ${esc(u.driver.summary)}.</p>`
      : `<p class="u-driver">No open findings. Nothing needs fixing right now.</p>`;
    el.innerHTML = `
      <div class="eyebrow">${host
        ? `Urgency · ${esc(host.agent_name)} <button type="button" class="chip-clear" data-clear-host style="margin-left:6px;text-transform:none;letter-spacing:0">Show all hosts</button>`
        : "Overall urgency"}</div>
      <div class="u-head">
        <div class="u-level">${shape(band, 16)}${esc(u.label)}</div>
        <div class="u-score" title="The priority of the most urgent open finding">${fmtScore(u.score)}<small> / 100</small></div>
      </div>
      ${driver}
      <div>
        ${stackBar(s.bands, OPEN, "stack")}
        <div class="legend" style="margin-top:8px">
          ${OPEN.map((b) => `<span class="item">${shape(b)}${esc(BAND_LABEL[b])} <b>${s.bands[b]}</b></span>`).join("")}
        </div>
      </div>
      <div class="sub-line">${host
        ? `${plural(s.open, "open finding")} on ${esc(host.agent_name)}${host.os ? ` (${esc(host.os)})` : ""} · last IoV evaluation ${host.last_evaluated ? relTime(host.last_evaluated) : "never"} · urgency is the priority of its most urgent open finding`
        : `${plural(s.open, "open finding")} · ${plural(u.hosts_at_risk, "host")} with findings to fix now or soon · urgency is the priority of the most urgent open finding`}</div>`;
  }

  function renderTiles() {
    const s = summary();
    const bands = Object.fromEntries(state.data.model.bands.map((b) => [b.key, b]));
    const f = state.filters;
    const tile = (opts) => `
      <button type="button" class="card tile${opts.static ? " static" : ""}${opts.active ? " active" : ""}" ${opts.filter ? `data-filter='${esc(JSON.stringify(opts.filter))}'` : ""}>
        <span class="label">${opts.icon || ""}${esc(opts.label)}</span>
        <span class="value">${opts.value}</span>
        ${opts.meter != null ? `<span class="meter"><span style="width:${Math.round(opts.meter * 100)}%"></span></span>` : ""}
        <span class="hint">${esc(opts.hint)}</span>
      </button>`;
    const iov = s.iov;
    const errs = iov.script_error_cves.length;
    $("#tiles").innerHTML = [
      ...OPEN.map((b) => tile({
        icon: shape(b), label: BAND_LABEL[b], value: s.bands[b], hint: bands[b].action,
        filter: { band: b, iov: "" }, active: f.band === b && !f.iov,
      })),
      tile({ icon: shape("not_affected"), label: "Ruled out by IoV", value: iov.ruled_out,
        hint: "Host and CVE pairs the IoV showed are not affected", filter: { band: "not_affected", iov: "" }, active: f.band === "not_affected" }),
      tile({ label: "Deprioritised by IoV", value: iov.deprioritised,
        hint: "Affected, but the exploitation preconditions are absent", filter: { band: "all", iov: "LOW" }, active: f.iov === "LOW" }),
      tile({ label: "IoV coverage", value: Math.round(iov.coverage * 100) + "%", meter: iov.coverage,
        hint: `${iov.conclusive} of ${s.total} findings have a conclusive verdict`, filter: { band: "open", iov: "NOT_ASSESSED" }, active: f.iov === "NOT_ASSESSED" }),
      tile({ label: "IoV check errors", value: errs,
        hint: errs ? `${plural(errs, "IoV")} failed on hosts; regenerate them` : "All IoV scripts ran cleanly", filter: errs ? { band: "all", iov: "ERROR" } : null, static: !errs, active: f.iov === "ERROR" }),
    ].join("");
  }

  function renderHostOptions() {
    const sel = $("#f-host");
    sel.innerHTML = `<option value="">All hosts</option>` +
      state.data.hosts.map((h) => `<option value="${esc(h.agent_id)}">${esc(h.agent_name)} (${esc(h.agent_id)})</option>`).join("");
  }

  function syncFilterInputs() {
    const f = state.filters;
    $("#f-q").value = f.q;
    $("#f-host").value = f.host;
    $("#f-band").value = f.band;
    $("#f-iov").value = f.iov;
    $("#f-clear").hidden = !(f.q || f.host || f.band !== "open" || f.iov);
  }

  function renderTab() {
    for (const t of ["findings", "hosts", "map"]) {
      $("#tab-" + t).hidden = state.tab !== t;
      document.querySelector(`.tab[data-tab="${t}"]`).setAttribute("aria-selected", String(state.tab === t));
    }
    if (state.tab === "findings") renderFindings();
    else if (state.tab === "hosts") renderHosts();
    else renderMap();
  }

  function filtered() {
    const f = state.filters;
    const q = f.q.trim().toLowerCase();
    return state.data.findings.filter((x) => {
      const band = x.priority.band.key;
      if (f.band === "open" && !OPEN.includes(band)) return false;
      if (!["open", "all"].includes(f.band) && band !== f.band) return false;
      if (f.host && x.agent_id !== f.host) return false;
      if (f.iov === "ERROR") { if (!(x.iov && x.iov.script_error)) return false; }
      else if (f.iov && x.priority.iov_level !== f.iov) return false;
      if (q) {
        const hay = [x.cve_id, x.agent_name, x.agent_id, x.priority.summary, x.iov && x.iov.reason,
          ...x.packages.map((p) => p.name + " " + (p.version || ""))].join(" ").toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }

  const SORTS = {
    rank: (x) => x.rank,
    cve: (x) => x.cve_id,
    host: (x) => x.agent_name,
    cvss: (x) => -(x.priority.factors[0].factor),
    epss: (x) => -(x.priority.factors[1].epss),
  };

  function renderFindings() {
    const rows = filtered();
    const { key, dir } = state.sort;
    if (key !== "rank") {
      const get = SORTS[key];
      rows.sort((a, b) => { const va = get(a), vb = get(b); return (va < vb ? -1 : va > vb ? 1 : a.rank - b.rank) * dir; });
    } else if (dir === -1) rows.reverse();

    $("#f-count").textContent = `${rows.length} of ${state.data.findings.length} findings`;
    const th = (k, label, cls) => {
      if (!k) return `<th class="${cls || ""}">${label}</th>`;
      const active = state.sort.key === k;
      const arrow = active ? (state.sort.dir === 1 ? "↓" : "↑") : "";
      return `<th class="${cls || ""}" aria-sort="${active ? (state.sort.dir === 1 ? "descending" : "ascending") : "none"}"><button type="button" data-sort="${k}" data-active="${active}">${label}<span aria-hidden="true">${arrow}</span></button></th>`;
    };
    const head = `<thead><tr>${th(null, "#")}${th("rank", "Priority")}${th("cve", "CVE")}${th("host", "Host")}${th(null, "Package")}${th("cvss", "CVSS", "num")}${th("epss", "EPSS", "num")}${th(null, "IoV verdict")}${th(null, "Why")}</tr></thead>`;

    if (!rows.length) {
      $("#findings-table").innerHTML = head + `<tbody><tr><td colspan="9" class="empty">No findings match these filters.</td></tr></tbody>`;
      $("#findings-more").hidden = true;
      return;
    }

    const body = rows.slice(0, state.limit).map((x) => {
      const p = x.priority;
      const band = p.band.key;
      const imp = p.factors[0], like = p.factors[1];
      const pkg = x.packages.length ? x.packages[0] : null;
      const pkgText = pkg ? `${pkg.name}${pkg.version ? " " + pkg.version : ""}` : "–";
      const more = x.packages.length > 1 ? ` <span class="sub-line">+${x.packages.length - 1}</span>` : "";
      return `<tr class="row${band === "not_affected" ? " dim" : ""}${state.selected === x.id ? " selected" : ""}" data-id="${esc(x.id)}" tabindex="0">
        <td class="rank">${x.rank}</td>
        <td><div class="prio"><span class="score">${fmtScore(p.score)}</span><span class="bar"><span style="width:${Math.max(2, p.score)}%;background:var(--band-${band})"></span></span>${bandLabel(band)}</div></td>
        <td class="cve">${esc(x.cve_id)}${x.source === "iov" ? `<div class="sub-line" title="Found by the IoV; Wazuh's detector does not report this CVE on this host">IoV only</div>` : ""}</td>
        <td class="host">${esc(x.agent_name)}</td>
        <td><div class="pkg" title="${esc(x.packages.map((q) => q.name + " " + (q.version || "")).join("\n"))}">${esc(pkgText)}</div>${more}</td>
        <td class="num" title="${esc(imp.assumed || "")}">${imp.assumed ? "~" : ""}${(imp.factor * 10).toFixed(1)}</td>
        <td class="num" title="${esc(like.assumed || fmtPct(like.percentile))}">${like.assumed ? "–" : fmtEpss(like.epss)}</td>
        <td>${iovChip(x)}</td>
        <td class="why">${esc(p.summary)}</td>
      </tr>`;
    }).join("");
    $("#findings-table").innerHTML = head + `<tbody>${body}</tbody>`;
    const moreBox = $("#findings-more");
    moreBox.hidden = rows.length <= state.limit;
    moreBox.querySelector("button").textContent = `Show more (${rows.length - state.limit} remaining)`;
  }

  function renderHosts() {
    const rows = state.data.hosts;
    const head = `<thead><tr><th>Host</th><th>Urgency</th><th class="num">Top priority</th><th>Open findings</th><th class="num">Fix now</th><th class="num">Fix soon</th><th class="num">Plan</th><th class="num">Low</th><th class="num">Not affected</th><th class="num" title="Sum of the priorities of all findings on the host">Risk load</th><th>Last IoV evaluation</th></tr></thead>`;
    const body = rows.map((h) => {
      const band = URGENCY_BAND[h.urgency.key];
      const age = ageDays(h.last_evaluated);
      const stale = age != null && age > 3;
      return `<tr class="row${h.agent_id === state.filters.host ? " selected" : ""}" data-host="${esc(h.agent_id)}" tabindex="0">
        <td><div class="host"><b>${esc(h.agent_name)}</b> <span class="sub-line">${esc(h.agent_id)}</span></div><div class="sub-line">${esc(h.os || "")}</div></td>
        <td><span class="band-label">${shape(band)}${esc(h.urgency.label)}</span></td>
        <td class="num"><b>${fmtScore(h.top_score)}</b></td>
        <td>${stackBar(h.bands, OPEN, "host-bands")}</td>
        ${BANDS.map((b) => `<td class="num">${h.bands[b] || `<span class="sub-line">0</span>`}</td>`).join("")}
        <td class="num">${Math.round(h.risk_load)}</td>
        <td>${h.last_evaluated ? relTime(h.last_evaluated) : `<span class="sub-line">never</span>`}${stale ? ` <span class="warn-text" title="The IoV daemon on this host may not be running">· stale</span>` : ""}</td>
      </tr>`;
    }).join("");
    $("#hosts-table").innerHTML = head + `<tbody>${body || `<tr><td colspan="11" class="empty">No hosts.</td></tr>`}</tbody>`;
  }

  // ── Risk map ────────────────────────────────────────────────────────────
  function renderMap() {
    const byCve = new Map();
    for (const f of scopedFindings()) {
      const c = byCve.get(f.cve_id) || { cve: f.cve_id, cvss: f.priority.factors[0].factor * 10, epss: f.priority.factors[1].epss,
        assumed: !!(f.priority.factors[0].assumed || f.priority.factors[1].assumed), hosts: 0, bands: {}, worst: null, top: 0 };
      c.hosts += 1;
      const b = f.priority.band.key;
      c.bands[b] = (c.bands[b] || 0) + 1;
      if (c.worst == null || BANDS.indexOf(b) < BANDS.indexOf(c.worst)) c.worst = b;
      c.top = Math.max(c.top, f.priority.score);
      byCve.set(f.cve_id, c);
    }
    const pts = [...byCve.values()].sort((a, b) => BANDS.indexOf(b.worst) - BANDS.indexOf(a.worst));

    const W = 760, H = 440, m = { l: 48, r: 20, t: 16, b: 44 };
    const iw = W - m.l - m.r, ih = H - m.t - m.b;
    const x = (e) => m.l + (Math.min(4, Math.max(0, Math.log10(Math.max(e, 1e-4)) + 4)) / 4) * iw;
    const y = (c) => m.t + ih - (c / 10) * ih;
    const xt = [[1e-4, "0.01%"], [1e-3, "0.1%"], [1e-2, "1%"], [1e-1, "10%"], [1, "100%"]];
    let svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Risk map: CVSS against EPSS, one dot per CVE">`;
    svg += `<g class="axis">`;
    for (const [v, label] of xt) svg += `<line class="gridline" x1="${x(v)}" x2="${x(v)}" y1="${m.t}" y2="${m.t + ih}"/><text x="${x(v)}" y="${H - m.b + 18}" text-anchor="middle">${label}</text>`;
    for (let c = 0; c <= 10; c += 2) svg += `<line class="gridline" x1="${m.l}" x2="${m.l + iw}" y1="${y(c)}" y2="${y(c)}"/><text x="${m.l - 8}" y="${y(c) + 4}" text-anchor="end">${c}</text>`;
    svg += `<text x="${m.l + iw / 2}" y="${H - 6}" text-anchor="middle">EPSS: probability of exploitation in the next 30 days →</text>`;
    svg += `<text transform="translate(12 ${m.t + ih / 2}) rotate(-90)" text-anchor="middle">CVSS base score →</text></g>`;
    for (const p of pts) {
      const r = Math.min(12, 5 + 2 * Math.sqrt(p.hosts - 1));
      svg += `<circle class="pt" data-cve="${esc(p.cve)}" cx="${x(p.epss).toFixed(1)}" cy="${y(p.cvss).toFixed(1)}" r="${r.toFixed(1)}" fill="var(--band-${p.worst})"${p.worst === "low" ? ` fill-opacity="0.9"` : ""}/>`;
    }
    svg += `</svg>`;
    $("#map-chart").innerHTML = svg;

    const counts = {};
    for (const p of pts) counts[p.worst] = (counts[p.worst] || 0) + 1;
    $("#map-legend").innerHTML = BANDS.map((b) => `<span class="item">${shape(b)}${esc(BAND_LABEL[b])} <b>${counts[b] || 0}</b> CVEs</span>`).join("");

    const tip = $("#tooltip");
    $("#map-chart").querySelectorAll("circle.pt").forEach((el) => {
      const p = byCve.get(el.dataset.cve);
      el.addEventListener("mousemove", (ev) => {
        tip.hidden = false;
        tip.innerHTML = `<b>${esc(p.cve)}</b>CVSS ${p.cvss.toFixed(1)} · EPSS ${fmtEpss(p.epss)}${p.assumed ? " (partly assumed)" : ""}<br>` +
          `${plural(p.hosts, "host")}: ` + BANDS.filter((b) => p.bands[b]).map((b) => `${p.bands[b]} ${BAND_LABEL[b].toLowerCase()}`).join(", ") +
          `<br><span class="sub-line">Top priority ${fmtScore(p.top)} · click to list</span>`;
        const tx = Math.min(ev.clientX + 14, window.innerWidth - tip.offsetWidth - 8);
        const ty = Math.min(ev.clientY + 14, window.innerHeight - tip.offsetHeight - 8);
        tip.style.left = tx + "px";
        tip.style.top = ty + "px";
      });
      el.addEventListener("mouseleave", () => { tip.hidden = true; });
      el.addEventListener("click", () => {
        tip.hidden = true;
        setFilters({ q: p.cve, band: "all", iov: "", host: "" });
        setTab("findings");
      });
    });
  }

  // ── Detail drawer ───────────────────────────────────────────────────────
  function openDrawer() {
    $("#drawer").hidden = false;
    $("#scrim").hidden = false;
    $("#drawer-close").focus();
  }
  function closeDrawer() {
    $("#drawer").hidden = true;
    $("#scrim").hidden = true;
    const prev = state.selected;
    state.selected = null;
    document.querySelectorAll("tr.row.selected").forEach((r) => r.classList.remove("selected"));
    const row = prev && document.querySelector(`tr.row[data-id="${CSS.escape(prev)}"]`);
    if (row) row.focus();
  }

  function openFinding(id, keepScroll) {
    const f = state.byId.get(id);
    if (!f) return;
    state.selected = id;
    document.querySelectorAll("tr.row").forEach((r) => r.classList.toggle("selected", r.dataset.id === id));
    const p = f.priority;
    const band = p.band.key;
    const links = state.data.links;
    const iovUrl = links.iov_server ? `${links.iov_server}/${encodeURIComponent(f.cve_id)}` : null;

    $("#drawer-head").innerHTML = `
      <div class="eyebrow">Rank ${f.rank} of ${state.data.findings.length}</div>
      <h2 id="drawer-title">${esc(f.cve_id)} <span style="font-weight:500;color:var(--ink-2)">on ${esc(f.agent_name)}</span></h2>
      <div class="d-score">
        <span class="big">${p.score.toFixed(1)}<small> / 100</small></span>
        <span>${bandLabel(band)}<div class="sub-line">${esc(p.band.action)}</div></span>
      </div>`;

    const factors = p.factors.map((fa) => `
      <div class="factor">
        <div class="name">${esc(fa.label)}<small>${esc(fa.source)}</small></div>
        <div class="fbar" role="img" aria-label="${esc(fa.label)} factor ${fa.factor.toFixed(2)}"><span style="width:${Math.max(1, fa.factor * 100)}%"></span></div>
        <div class="fval">×${fa.factor.toFixed(2)}</div>
        <div class="fdetail"><b>${esc(fa.display)}</b> · ${esc(fa.detail)}
          ${fa.assumed ? `<p class="note warn">${esc(fa.assumed)}</p>` : ""}
          ${(fa.notes || []).map((n) => `<p class="note warn">${esc(n)}</p>`).join("")}
        </div>
      </div>`).join("");
    const [fi, fl, fa] = p.factors;
    const formula = `100 × ${fi.factor.toFixed(2)} × ${fl.factor.toFixed(2)} × ${fa.factor.toFixed(2)} = ${p.score.toFixed(1)}`;

    let whatIf = "";
    if (p.what_if) {
      whatIf = `<section><h3>What an IoV verdict would change</h3>
        <p>${p.iov_level === "NOT_ASSESSED" ? "There is no IoV for this CVE yet." : p.iov_level === "MEDIUM" ? "The IoV cannot tell whether the preconditions hold on this host." : "The IoV gave no verdict on this host."} A verdict would move it to:</p>
        <div class="whatif">
          <div><div class="k">Preconditions present (HIGH)</div><div class="v">${p.what_if.HIGH.score.toFixed(1)}</div><div class="sub-line">${esc(p.what_if.HIGH.band)}</div></div>
          <div><div class="k">Preconditions absent (LOW)</div><div class="v">${p.what_if.LOW.score.toFixed(1)}</div><div class="sub-line">${esc(p.what_if.LOW.band)}</div></div>
        </div></section>`;
    }

    let iovSection;
    if (f.iov) {
      const iv = f.iov;
      const age = ageDays(iv.evaluated_at);
      iovSection = `<section><h3>IoV verdict on this host</h3>
        <p>${iovChip(f)}</p>
        <dl class="kv">
          <dt>Reason</dt><dd>${esc(iv.reason || "–")}</dd>
          <dt>Evaluated</dt><dd>${relTime(iv.evaluated_at)}${age != null && age > 3 ? ` <span class="warn-text">· stale</span>` : ""}</dd>
          <dt>Script</dt><dd>${iv.script_ran ? "ran" : "not run (package check only)"}${iv.script_result != null ? `, returned ${esc(iv.script_result)}` : ""}</dd>
          <dt>IoV</dt><dd class="mono">${esc(iv.uuid || "–")}</dd>
        </dl>
        ${iv.script_error ? `<pre class="err">${esc(iv.script_error)}</pre>` : ""}
        <details class="evaluated-iov" id="evaluated-iov">
          <summary>IoV as evaluated on this host</summary>
          <div class="evaluated-iov-body"><p class="sub-line">Loading…</p></div>
        </details>
      </section>`;
    } else {
      iovSection = `<section><h3>IoV verdict on this host</h3><p>${iovChip(f)}</p>
        <p class="sub-line">No Indicator of Vulnerability exists for this CVE yet${links.iov_server ? "; queue one on the IoV server (<code>cli.py queue-iovs</code>)" : ""}. It is ranked on CVSS and EPSS with a neutral applicability.</p></section>`;
    }

    const pkgs = f.packages.length ? `<table><thead><tr><th>Package</th><th>Version</th><th>IoV state</th></tr></thead><tbody>${
      f.packages.map((q) => `<tr><td class="mono">${esc(q.name)}</td><td class="mono">${esc(q.version || "–")}</td><td>${esc(q.state || "–")}</td></tr>`).join("")}</tbody></table>` : `<p class="sub-line">No package information.</p>`;
    const det = f.wazuh;
    const detection = `<section><h3>Detection</h3>
      <dl class="kv">
        <dt>Source</dt><dd>${f.source === "both" ? "Wazuh vulnerability detector + IoV" : f.source === "wazuh" ? "Wazuh vulnerability detector" : "IoV only (not detected by Wazuh)"}</dd>
        ${f.os ? `<dt>OS</dt><dd>${esc(f.os)}</dd>` : ""}
        ${det && det.severity ? `<dt>Scanner severity</dt><dd>${esc(det.severity)}</dd>` : ""}
        ${det && det.published_at ? `<dt>Published</dt><dd>${esc(fmtDate(det.published_at))}</dd>` : ""}
        ${det && det.detected_at ? `<dt>Detected</dt><dd>${relTime(det.detected_at)}</dd>` : ""}
      </dl>
      ${det ? `<p id="det-desc" style="margin-top:10px"${det.description ? "" : " hidden"}>${esc(det.description || "")}</p>` : ""}
      <div style="margin-top:10px">${pkgs}</div></section>`;

    const vector = fi.vector && fi.vector.length ? `<section><h3>CVSS ${esc(fi.version || "")} vector</h3>
      <dl class="kv">${fi.vector.map((v) => `<dt>${esc(v.name)}</dt><dd>${esc(v.value)}</dd>`).join("")}</dl>
      <p class="sub-line mono" style="margin-top:8px">${esc(fi.vector_string)}</p></section>` : "";

    const others = state.data.findings.filter((o) => o.cve_id === f.cve_id && o.id !== f.id);
    const otherHtml = others.length ? `<section><h3>Same CVE on ${plural(others.length, "other host")}</h3><div class="others">${
      others.map((o) => `<button type="button" data-open="${esc(o.id)}">${shape(o.priority.band.key)}<span class="grow"><b>${esc(o.agent_name)}</b> <span class="sub-line">${esc((IOV[o.priority.iov_level] || {}).label || "")}</span></span><span>${fmtScore(o.priority.score)}</span></button>`).join("")
    }</div></section>` : "";

    const linkHtml = `<section><h3>Links</h3><div class="links">
      ${iovUrl ? `<a class="primary" href="${esc(iovUrl)}" target="_blank" rel="noopener">IoV on the IoV server ↗</a>` : ""}
      <a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(f.cve_id)}" target="_blank" rel="noopener">NVD ↗</a>
      <a href="https://www.cve.org/CVERecord?id=${encodeURIComponent(f.cve_id)}" target="_blank" rel="noopener">CVE.org ↗</a>
      <a href="https://api.first.org/data/v1/epss?cve=${encodeURIComponent(f.cve_id)}&scope=time-series" target="_blank" rel="noopener">EPSS history ↗</a>
    </div></section>`;

    // A refresh re-renders the open finding; keep the evaluated IoV open.
    const evaluatedWasOpen = Boolean(keepScroll && $("#evaluated-iov") && $("#evaluated-iov").open);
    $("#drawer-body").innerHTML = `
      <section><h3>Why it is ranked here</h3>
        <p>${esc(p.summary)}.</p>
        <div class="factors">${factors}</div>
        <div class="formula">${esc(formula)}</div>
      </section>
      ${whatIf}
      ${iovSection}
      <section id="iov-doc" hidden></section>
      ${detection}
      ${vector}
      ${otherHtml}
      ${linkHtml}`;
    if (!keepScroll) $("#drawer-body").scrollTop = 0;
    if (!keepScroll || $("#drawer").hidden) openDrawer();
    const evaluated = $("#evaluated-iov");
    if (evaluated) {
      // Fetched only when opened: IoVs are several KB each.
      evaluated.addEventListener("toggle", () => { if (evaluated.open) loadEvaluatedIov(f, evaluated); });
      if (evaluatedWasOpen) evaluated.open = true;
    }
    if (f.iov || links.iov_server) loadIovDoc(f.cve_id, iovUrl);
    if (det && !det.description) loadDescription(f);
  }

  // The findings list leaves out the scanner's descriptions; fetch the one shown.
  const descCache = new Map();
  async function loadDescription(f) {
    let text = descCache.get(f.id);
    if (text === undefined) {
      try {
        const resp = await fetch(`api/detection/${encodeURIComponent(f.agent_id)}/${encodeURIComponent(f.cve_id)}`);
        text = resp.ok ? (await resp.json()).description || "" : "";
      } catch (e) { text = ""; }
      descCache.set(f.id, text);
    }
    const box = $("#det-desc");
    if (!text || state.selected !== f.id || !box) return;
    box.textContent = text;
    box.hidden = false;
  }

  // Per verdict: a re-evaluation brings a new evaluated_at, and possibly a new IoV.
  const evaluatedIovCache = new Map();
  async function loadEvaluatedIov(f, box) {
    const key = `${f.id}@${f.iov.evaluated_at}`;
    let entry = evaluatedIovCache.get(key);
    if (entry === undefined) {
      try {
        const resp = await fetch(`api/evaluated-iov/${encodeURIComponent(f.agent_id)}/${encodeURIComponent(f.cve_id)}`);
        const body = await resp.json().catch(() => ({}));
        entry = resp.ok ? { iov: body } : { error: body.detail || `The request failed (HTTP ${resp.status}).` };
        if (resp.ok || resp.status === 404) evaluatedIovCache.set(key, entry);
      } catch (e) {
        entry = { error: "ETSO could not be reached." };  // not cached: try again on the next open
      }
    }
    const target = box.querySelector(".evaluated-iov-body");
    if (state.selected !== f.id || !box.isConnected || !target) return;
    target.innerHTML = entry.error ? `<p class="sub-line">${esc(entry.error)}</p>` : evaluatedIovHtml(entry.iov);
  }

  function evaluatedIovHtml(iov) {
    const doc = iov.document;
    const packages = doc.packages && typeof doc.packages === "object" ? Object.keys(doc.packages) : [];
    return `
      ${doc.description ? `<div class="iov-desc">${esc(doc.description)}</div>` : ""}
      <dl class="kv" style="margin-top:10px">
        <dt>IoV</dt><dd class="mono">${esc(doc.uuid || iov.uuid || "–")}</dd>
        ${doc.schema_version != null ? `<dt>Format</dt><dd>version ${esc(doc.schema_version)}</dd>` : ""}
        <dt>Packages</dt><dd>${packages.length ? esc(packages.join(", ")) : "none"}</dd>
      </dl>
      ${doc.script ? `<h4>Precondition script</h4><pre class="code">${esc(doc.script)}</pre>` : ""}
      <details class="evaluated-iov-raw"><summary>Full document (JSON)</summary>
        <pre class="code">${esc(JSON.stringify(doc, null, 2))}</pre>
      </details>`;
  }

  const iovDocCache = new Map();
  async function loadIovDoc(cve, iovUrl) {
    const box = $("#iov-doc");
    let doc = iovDocCache.get(cve);
    if (doc === undefined) {
      try {
        const resp = await fetch("api/iov/" + encodeURIComponent(cve));
        doc = resp.ok ? await resp.json() : null;
      } catch (e) { doc = null; }
      iovDocCache.set(cve, doc);
    }
    if (!doc || state.selected == null || !state.selected.endsWith(":" + cve) || !box) return;
    const refs = (doc.references || []).slice(0, 8).map((r) => {
      const label = esc([r.source, r.id].filter(Boolean).join(" "));
      return r.url ? `<a href="${esc(r.url)}" target="_blank" rel="noopener">${label} ↗</a>` : `<span>${label}</span>`;
    }).join("");
    box.innerHTML = `<h3>About this IoV</h3>
      ${doc.description ? `<div class="iov-desc">${esc(doc.description)}</div>` : ""}
      <dl class="kv" style="margin-top:10px">
        <dt>Checks</dt><dd>${doc.packages.length ? "packages " + esc(doc.packages.join(", ")) : "no package ranges"}${doc.has_script ? " + precondition script" : ""}</dd>
        ${doc.updated ? `<dt>Updated</dt><dd>${relTime(doc.updated)}</dd>` : ""}
      </dl>
      ${refs ? `<div class="links" style="margin-top:10px">${refs}</div>` : ""}
      ${iovUrl ? `<p style="margin-top:10px"><a href="${esc(iovUrl)}" target="_blank" rel="noopener">Full IoV document ↗</a></p>` : ""}`;
    box.hidden = false;
  }

  function openHelp() {
    const m = state.data ? state.data.model : null;
    state.selected = null;
    $("#drawer-head").innerHTML = `<div class="eyebrow">Method</div><h2 id="drawer-title">How ranking works</h2>`;
    const iovRows = m ? Object.entries(m.iov_factors).map(([k, v]) => `<tr><td>${esc(v.label)}</td><td class="num">×${v.factor.toFixed(2)}</td><td>${esc(v.text)}</td></tr>`).join("") : "";
    const bandRows = m ? m.bands.map((b) => `<tr><td>${bandLabel(b.key)}</td><td class="num">${b.key === "not_affected" ? "IoV ABSENT" : "≥ " + (b.min < 1 ? "0" : b.min)}</td><td>${esc(b.action)}</td></tr>`).join("") : "";
    $("#drawer-body").innerHTML = `<div class="help">
      <section><h3>The score</h3>
        <p>Every (host, CVE) pair gets a priority from 0 to 100:</p>
        <div class="formula">${esc(m ? m.formula : "")}</div>
        <p style="margin-top:12px"><b>Impact</b> is the CVSS base score divided by 10: how bad a successful exploit is.</p>
        <p><b>Likelihood</b> comes from EPSS, the probability that the CVE is exploited in the wild in the next 30 days. EPSS is heavily skewed, so it is read on a log scale (0.01% → 0, 0.1% → 0.25, 1% → 0.5, 10% → 0.75, 100% → 1) and never drops below ${m ? m.likelihood_floor : 0.3}, because a low EPSS predicts little activity but does not rule it out. A CVE without an EPSS score yet is assumed at ${m ? (m.epss_assumed * 100).toFixed(0) : 1}%.</p>
        <p><b>Applicability</b> is what the host's Indicator of Vulnerability found. This is the part only IoV can add: whether the exploitation preconditions are actually present on <em>this</em> host.</p>
      </section>
      <section><h3>IoV verdicts</h3>
        <table><thead><tr><th>Verdict</th><th class="num">Factor</th><th>Meaning</th></tr></thead><tbody>${iovRows}</tbody></table>
        <p class="note">No verdict, an inconclusive verdict and a failed IoV script all rank neutrally, exactly like "affected, preconditions unknown". A missing IoV never makes a finding look safer than it is.</p>
      </section>
      <section><h3>Priority bands</h3>
        <table><thead><tr><th>Band</th><th class="num">Score</th><th>Suggested action</th></tr></thead><tbody>${bandRows}</tbody></table>
      </section>
      <section><h3>Overall urgency</h3>
        <p>The urgency card shows the priority of the single most urgent open finding: an estate is only as urgent as its worst open problem. The bar beneath it shows how the open findings split across the bands.</p>
      </section>
      <section><h3>Data</h3>
        <p>${state.data ? esc(state.data.source.label) + ": <code>" + esc(state.data.source.detail) + "</code>." : ""} IoV verdicts are published by the agents' IoV daemon and projected by ETSO together with EPSS (FIRST) and CVSS (NVD). ${state.data && state.data.source.detections ? "CVEs Wazuh detected without an IoV are included and ranked on CVSS and EPSS alone." : ""}</p>
      </section></div>`;
    openDrawer();
  }

  // ── State changes ───────────────────────────────────────────────────────
  function setFilters(patch) {
    Object.assign(state.filters, patch);
    state.limit = PAGE;
    syncFilterInputs();
    renderOverview();
    renderTab();
    writeUrl();
  }
  function setTab(tab) {
    state.tab = tab;
    renderTab();
    writeUrl();
  }
  function writeUrl() {
    const params = new URLSearchParams(location.search);
    const f = state.filters;
    const set = (k, v, def) => (v && v !== def ? params.set(k, v) : params.delete(k));
    set("q", f.q); set("host", f.host); set("band", f.band, "open"); set("iov", f.iov); set("tab", state.tab, "findings");
    const qs = params.toString();
    history.replaceState(null, "", location.pathname + (qs ? "?" + qs : ""));
  }
  function readUrl() {
    const params = new URLSearchParams(location.search);
    state.filters.q = params.get("q") || "";
    state.filters.host = params.get("host") || "";
    state.filters.band = params.get("band") || "open";
    state.filters.iov = (params.get("iov") || "").toUpperCase();
    state.openOnLoad = params.get("open");
    const tab = params.get("tab");
    if (["findings", "hosts", "map"].includes(tab)) state.tab = tab;
  }
  function resolveHostParam() {
    // ?host= may be an agent name (what a Wazuh link knows) or an ID.
    const h = state.filters.host;
    if (!h || !state.data) return;
    const match = state.data.hosts.find((x) => x.agent_id === h || x.agent_name === h);
    state.filters.host = match ? match.agent_id : "";
  }

  // ── Events ──────────────────────────────────────────────────────────────
  function bind() {
    let qTimer;
    $("#f-q").addEventListener("input", (e) => { clearTimeout(qTimer); qTimer = setTimeout(() => setFilters({ q: e.target.value }), 150); });
    $("#f-host").addEventListener("change", (e) => setFilters({ host: e.target.value }));
    $("#f-band").addEventListener("change", (e) => setFilters({ band: e.target.value }));
    $("#f-iov").addEventListener("change", (e) => setFilters({ iov: e.target.value }));
    $("#f-clear").addEventListener("click", () => setFilters({ q: "", host: "", band: "open", iov: "" }));
    $("#refresh-btn").addEventListener("click", () => load(true));
    $("#help-btn").addEventListener("click", openHelp);
    $("#drawer-close").addEventListener("click", closeDrawer);
    $("#scrim").addEventListener("click", closeDrawer);
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("#drawer").hidden) closeDrawer(); });
    $("#findings-more button").addEventListener("click", () => { state.limit += PAGE * 2; renderFindings(); });

    document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => setTab(t.dataset.tab)));

    document.addEventListener("click", (e) => {
      if (e.target.closest("[data-clear-host]")) { setFilters({ host: "" }); return; }
      const opener = e.target.closest("[data-open]");
      if (opener) { e.preventDefault(); openFinding(opener.dataset.open); return; }
      const tile = e.target.closest(".tile[data-filter]");
      if (tile) { setFilters(JSON.parse(tile.dataset.filter)); setTab("findings"); return; }
      const sortBtn = e.target.closest("th button[data-sort]");
      if (sortBtn) {
        const k = sortBtn.dataset.sort;
        state.sort = state.sort.key === k ? { key: k, dir: -state.sort.dir } : { key: k, dir: 1 };
        renderFindings();
        return;
      }
      const row = e.target.closest("tr.row");
      if (row && row.dataset.id) openFinding(row.dataset.id);
      else if (row && row.dataset.host) { setFilters({ host: row.dataset.host, band: "open", iov: "", q: "" }); setTab("findings"); }
    });
    document.addEventListener("keydown", (e) => {
      if (e.key !== "Enter") return;
      const row = e.target.closest && e.target.closest("tr.row");
      if (row) row.click();
    });
  }

  readUrl();
  bind();
  load(false).then(() => {
    if (!state.data) return;
    if (state.openOnLoad === "help") openHelp();
    else if (state.openOnLoad) openFinding(state.openOnLoad);
  });
  setInterval(() => { if (document.visibilityState === "visible") load(false); }, AUTO_REFRESH_MS);
})();
