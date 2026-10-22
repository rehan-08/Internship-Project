// Officer review UI. Analysis data arrives MASKED; PII is rehydrated here, at
// render time, from the officer-only /rehydration endpoint and never cached.
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const TOKEN_RE = /\[(?:CLIENT|SSN|EMAIL|PHONE|ADDRESS|ACCOUNT|AMOUNT|DOB)_\d+\]/g;
const DOC_TYPE_LABEL = {
  INVESTMENT_AGREEMENT: "Investment agreement", ACCOUNT_AGREEMENT: "Account agreement",
  NEWSLETTER: "Newsletter", BROCHURE: "Brochure",
};
const ROW_LABEL = { SEC: "Security alerts", CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", ABSENCE: "Missing disclosures" };
const CATEGORIES = [
  { key: "SEC", label: "Security", color: "var(--sec)" },
  { key: "CRITICAL", label: "Critical", color: "var(--crit)" },
  { key: "HIGH", label: "High", color: "var(--high)" },
  { key: "MEDIUM", label: "Medium", color: "var(--med)" },
  { key: "LOW", label: "Low", color: "var(--low)" },
  { key: "ABSENCE", label: "Missing", color: "var(--abs)" },
];
const ICONS = {
  warn: '<svg width="16" height="16" viewBox="0 0 24 24"><path fill="currentColor" d="M1 21 12 2l11 19H1Zm11-3q.4 0 .7-.3t.3-.7q0-.4-.3-.7T12 16q-.4 0-.7.3t-.3.7q0 .4.3.7t.7.3Zm-1-3h2v-5h-2v5Z"/></svg>',
  shield: '<svg width="16" height="16" viewBox="0 0 24 24"><path fill="currentColor" d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3Z"/></svg>',
  info: '<svg width="16" height="16" viewBox="0 0 24 24"><path fill="currentColor" d="M11 17h2v-6h-2v6Zm1-8q.4 0 .7-.3T13 8q0-.4-.3-.7T12 7q-.4 0-.7.3T11 8q0 .4.3.7t.7.3Zm0 13q-2.1 0-3.9-.8t-3.2-2.1q-1.3-1.4-2.1-3.2T2 12q0-2.1.8-3.9t2.1-3.2Q6.3 3.6 8.1 2.8T12 2q2.1 0 3.9.8t3.2 2.1q1.4 1.4 2.1 3.2T22 12q0 2.1-.8 3.9t-2.1 3.2q-1.4 1.4-3.2 2.1T12 22Z"/></svg>',
  check: '<svg width="20" height="20" viewBox="0 0 24 24"><path fill="currentColor" d="m9.6 18-5.7-5.7 1.4-1.4 4.3 4.3 9.2-9.2 1.4 1.4L9.6 18Z"/></svg>',
  alert: '<svg width="20" height="20" viewBox="0 0 24 24"><path fill="currentColor" d="M1 21 12 2l11 19H1Zm11-3q.4 0 .7-.3t.3-.7q0-.4-.3-.7T12 16q-.4 0-.7.3t-.3.7q0 .4.3.7t.7.3Zm-1-3h2v-5h-2v5Z"/></svg>',
  eye: '<svg width="20" height="20" viewBox="0 0 24 24"><path fill="currentColor" d="M12 16q1.9 0 3.2-1.3T16.5 11.5q0-1.9-1.3-3.2T12 7q-1.9 0-3.2 1.3T7.5 11.5q0 1.9 1.3 3.2T12 16Zm0 4q-3.7 0-6.6-2.1T1 12q1.5-3.8 4.4-5.9T12 4q3.7 0 6.6 2.1T23 12q-1.5 3.8-4.4 5.9T12 20Z"/></svg>',
  lock: '<svg width="16" height="16" viewBox="0 0 24 24"><path fill="currentColor" d="M6 22q-.8 0-1.4-.6T4 20V10q0-.8.6-1.4T6 8h1V6q0-2.1 1.5-3.5T12 1q2.1 0 3.5 1.5T17 6v2h1q.8 0 1.4.6T20 10v10q0 .8-.6 1.4T18 22H6Zm3-14h6V6q0-1.3-.9-2.1T12 3q-1.3 0-2.1.9T9 6v2Z"/></svg>',
};

const state = { user: null, health: null, docId: null, review: null, vault: null, masked: false, focus: null, hidden: new Set() };

// ------------------------------------------------------------ utilities
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.hidden = false;
  t.style.animation = "none"; void t.offsetWidth; t.style.animation = "";
  clearTimeout(toast._t); toast._t = setTimeout(() => (t.hidden = true), 2800);
}
// Swallow errors from background refreshes; 401s already route to the sign-in screen.
const quiet = (e) => { if (state.user) toast(e.message.replace(/^\d+\s/, "")); };
function officer() { return state.user?.display_name || ""; }
function store(k, v) { try { v === undefined ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch {} }
function load(k) { try { return localStorage.getItem(k); } catch { return null; } }
async function api(path, opts = {}) {
  const res = await fetch(path, { credentials: "same-origin", ...opts });
  if (res.status === 401 && !path.startsWith("/api/auth/")) {
    showLogin("Your session has ended. Please sign in again.");
    throw new Error("Not signed in");
  }
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch {}
    throw new Error(`${res.status} ${detail}`);
  }
  return res.json();
}
const ext = (name) => (name.split(".").pop() || "txt").toLowerCase();
const ftype = (name) => { const e = ext(name); return `<span class="ftype ${e === "md" ? "txt" : e}">${esc(e.toUpperCase())}</span>`; };
const pretty = (name) => name.replace(/\.[a-z]+$/i, "").replace(/^RedTeam_/, "").replace(/_(?!\d+\])/g, " ");  // keep [CLIENT_1] intact
const statusLabel = (s) => ({ PENDING_REVIEW: "Pending review", APPROVED: "Approved", REJECTED: "Rejected" }[s] || s);
function timeAgo(ts) {
  const s = Math.max(1, Math.round(Date.now() / 1000 - ts));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return new Date(ts * 1000).toLocaleDateString();
}

// ------------------------------------------------------------ rehydration
/** Render masked text [absStart, absStart+text.length) with tokens rehydrated. */
function renderText(text, absStart = null, { forceMask = false } = {}) {
  let out = "", last = 0;
  for (const m of text.matchAll(TOKEN_RE)) {
    out += esc(text.slice(last, m.index));
    const tok = m[0];
    // A vault only ever rehydrates its own document; a stale one (mid-switch) is ignored.
    if (forceMask || state.masked || !state.vault || state.vault.docId !== state.docId) {
      out += `<span class="tok">${esc(tok)}</span>`;
    } else {
      const occ = absStart != null ? state.vault.occByStart.get(absStart + m.index) : null;
      const real = occ && occ.token === tok ? occ.original : state.vault.tokens[tok];
      out += real != null ? `<span class="pii" title="${esc(tok)}">${esc(real)}</span>` : `<span class="tok">${esc(tok)}</span>`;
    }
    last = m.index + tok.length;
  }
  return out + esc(text.slice(last));
}

// ------------------------------------------------------------------ left
// Sidebar loaders are fire-and-forget from many places: they handle their own failures
// (a 401 has already switched to the sign-in screen) and never render after sign-out.
async function loadSamples() {
  let names;
  try { names = await api("/api/samples"); } catch { return; }
  if (!state.user) return;
  $("#samplesSection").hidden = !names.length;
  $("#tryDemo").hidden = !names.includes("Investment_Agreement_Jane_Smith.txt");
  const demo = names.filter((n) => !n.startsWith("RedTeam_"));
  const red = names.filter((n) => n.startsWith("RedTeam_"));
  const btn = (n) => `<button data-sample="${esc(n)}" title="${esc(n)}">${ftype(n)}<span class="nm">${esc(pretty(n))}</span></button>`;
  $("#samples").innerHTML =
    (demo.length ? `<div class="sample-group">Demo documents</div>${demo.map(btn).join("")}` : "") +
    (red.length ? `<div class="sample-group">Red-team attacks</div>${red.map(btn).join("")}` : "");
}
async function loadQueue() {
  let docs;
  try { docs = await api("/api/documents"); } catch { return; }
  if (!state.user) return;
  $("#queueCount").textContent = docs.length || "";
  const tally = { PENDING_REVIEW: 0, APPROVED: 0, REJECTED: 0, TOTAL: docs.length };
  docs.forEach((d) => { tally[d.status] = (tally[d.status] || 0) + 1; });
  $$("#queueStats [data-stat]").forEach((el) => (el.textContent = tally[el.dataset.stat] ?? 0));
  $("#queue").innerHTML = docs.map((d) => `
    <li data-id="${esc(d.id)}" class="${d.id === state.docId ? "active" : ""}" title="${esc(d.filename)}">
      ${ftype(d.filename)}<div class="name">${renderText(pretty(d.filename), null, { forceMask: d.id !== state.docId })}</div>
      <div class="sub"><span class="dot ${d.status}"></span>${statusLabel(d.status)} · ${esc(DOC_TYPE_LABEL[d.doc_type] || d.doc_type)} · ${timeAgo(d.created_at)}</div>
    </li>`).join("") || `<li class="empty-q">Nothing in the queue yet.</li>`;
}

async function ingestSample(name) {
  await ingest(() => api(`/api/samples/${encodeURIComponent(name)}`, { method: "POST" }));
}
async function uploadFile(file) {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("doc_type", $("#docType").value);
  await ingest(() => api("/api/documents", { method: "POST", body: fd }));
}
async function ingest(request) {
  const previous = state.docId;
  showLoading();
  let id;
  try {
    ({ id } = await request());
  } catch (e) {
    if (!state.user) return;  // signed out mid-request: the sign-in screen is already up
    toast(e.message.replace(/^\d+\s/, ""));
    // Don't leave the loading skeleton up: go back to where the officer was.
    if (previous) openDoc(previous); else resetWorkspace();
    return;
  }
  await openDoc(id);
}

// --------------------------------------------------------------- loading
let stageTimers = [];
function setDecisionEnabled(on) {
  $$("[data-decision]").forEach((b) => (b.disabled = !on));
}
function showLoading() {
  setDecisionEnabled(false);
  $("#empty").hidden = true; $("#docView").hidden = false; $("#rightPane").hidden = false;
  $("#banners").innerHTML = ""; $("#rail").innerHTML = "";
  $("#docTitle").textContent = "Analyzing…"; $("#docMeta").innerHTML = ""; $("#docFtype").outerHTML = '<span class="ftype" id="docFtype"></span>';
  $("#verdict").innerHTML = `<div class="skel" style="width:60%;height:16px"></div><div class="skel" style="width:85%;margin-top:10px"></div>`;
  $("#findings").innerHTML = [1, 2, 3].map(() => `<div class="flag"><div class="skel" style="width:40%"></div><div class="skel" style="width:90%;margin-top:10px"></div><div class="skel" style="width:70%;margin-top:6px"></div></div>`).join("");
  const stages = ["Extracting text and masking client PII", "Inspecting each section against 10 rules", "Validating quotes, checking disclosures and precedents"];
  $("#docText").innerHTML = `<div class="loading">${stages.map((s, i) => `<div class="stage" id="stage${i}"><span class="ic"><span class="spinner"></span></span>${s}</div>`).join("")}
    <div class="skel" style="width:92%;margin-top:14px"></div><div class="skel" style="width:78%"></div><div class="skel" style="width:85%"></div><div class="skel" style="width:60%"></div></div>`;
  stageTimers.forEach(clearTimeout);
  const set = (i) => { for (let j = 0; j < 3; j++) { const el = $(`#stage${j}`); if (!el) return; el.classList.toggle("on", j === i); el.classList.toggle("done", j < i); } };
  set(0);
  stageTimers = [setTimeout(() => set(1), 450), setTimeout(() => set(2), 1500)];
}

// --------------------------------------------------------------- document
async function openDoc(id, refresh = false) {
  if (state.docId !== id) {
    state.hidden = new Set();
    $("#notes").value = "";  // a note typed for one document must never be filed against another
  }
  // Nothing may act on the previous document's analysis while this one loads.
  Object.assign(state, { docId: id, review: null, vault: null, focus: null });
  resetConfirm();
  if (!$("#docText .loading")) showLoading();
  $("#rerun").disabled = true;
  loadQueue();
  try {
    const review = await api(`/api/documents/${id}/analyze?refresh=${refresh}`, { method: "POST" });
    if (state.docId !== id) return;  // user switched documents while this was loading
    state.review = review;
    await loadVault();
    render();
    $("#center").scrollTop = 0;
    await loadQueue();  // re-render the active item with this document's vault
    // On phones the document sits below the queue: bring it into view (after the queue reflowed).
    if (matchMedia("(max-width: 760px)").matches) window.scrollTo({ top: $("#center").offsetTop });
  } catch (e) {
    if (!state.user || state.docId !== id) return;  // signed out, or the officer moved on
    $("#docTitle").textContent = "Couldn't open this document";
    $("#docText").innerHTML = `<div class="banner err"><span class="bi">${ICONS.warn}</span><span><b>Analysis failed.</b> ${esc(e.message.replace(/^\d+\s/, ""))} Use Re-run to try again.</span></div>`;
    $("#verdict").innerHTML = "";
    $("#findings").innerHTML = `<div class="none">No findings, because the analysis did not complete.</div>`;
  } finally {
    stageTimers.forEach(clearTimeout);
    $("#rerun").disabled = false;
  }
}
async function loadVault() {
  state.vault = null;
  const docId = state.docId;
  if (!state.user || !docId) return;
  try {
    const v = await api(`/api/documents/${docId}/rehydration`);
    v.occByStart = new Map(v.occurrences.map((o) => [o.start, o]));
    v.docId = docId;
    if (state.docId === docId) state.vault = v;
  } catch (e) { toast(e.message); }
}

const category = (f) => (f.type === "absence" ? "ABSENCE" : f.type === "security" ? "SEC" : f.severity);
function allFlags() {
  const r = state.review;
  return [
    ...r.security.prompt_injection.map((s, i) => ({ ...s, id: `S-${i}`, type: "security", severity: "CRITICAL" })),
    ...r.inspection.flags,
    ...r.absence.flags,
  ];
}
const visibleFlags = () => allFlags().filter((f) => !state.hidden.has(category(f)));

function render() {
  const r = state.review, doc = r.document, ins = r.inspection;
  $("#docFtype").outerHTML = ftype(doc.filename).replace('class="ftype', 'id="docFtype" class="ftype');
  $("#docTitle").innerHTML = renderText(pretty(doc.filename));
  const sep = '<span class="sep">·</span>';
  const masked = r.security.pii_entities ?? 0;
  $("#docMeta").innerHTML = [
    `<span class="status ${r.review_status}">${statusLabel(r.review_status)}</span>`,
    esc(DOC_TYPE_LABEL[doc.doc_type] || doc.doc_type),
    `${ins.sections.length} sections`,
    `<span title="Client details replaced with tokens before analysis">${masked} detail${masked === 1 ? "" : "s"} masked</span>`,
    `<span title="${esc(`${doc.id} · ${ins.model_id} · ${ins.prompt_version}`)}">${ins.cache === "hit" ? "Cached" : `Analyzed in ${(ins.elapsed_ms / 1000).toFixed(1)}s`}</span>`,
  ].join(sep);
  $$(".seg button").forEach((b) => b.classList.toggle("on", (b.dataset.view === "masked") === state.masked));
  setDecisionEnabled(true);
  renderVerdict();
  renderBanners();
  renderDocument();
  renderFindings();
  renderPrecedents();
  renderDecisions();
}

function renderVerdict() {
  const r = state.review, ins = r.inspection;
  const flags = allFlags();
  const counts = Object.fromEntries(CATEGORIES.map((c) => [c.key, flags.filter((f) => category(f) === c.key).length]));
  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
  let cls, title, sub;
  if (ins.ai_status === "UNAVAILABLE") {
    [cls, title, sub] = ["risk-na", "Manual review required", "Automated inspection was unavailable for this document."];
  } else if (counts.SEC || counts.CRITICAL) {
    [cls, title, sub] = ["risk-high", "High risk", [counts.CRITICAL && plural(counts.CRITICAL, "critical violation"),
      counts.SEC && plural(counts.SEC, "security alert")].filter(Boolean).join(" and ") + "."];
  } else if (ins.flags.length || counts.ABSENCE) {
    [cls, title, sub] = ["risk-mid", "Needs review", `${plural(ins.flags.length, "violation")}, ${plural(counts.ABSENCE, "missing disclosure")}.`];
  } else {
    [cls, title, sub] = ["risk-ok", "No issues found", "No rule violations; all required disclosures present."];
  }
  // Risk score 0-100: severity-weighted sum on a saturating curve, so documents stay comparable.
  const raw = counts.SEC * 30 + counts.CRITICAL * 24 + counts.HIGH * 12 + counts.MEDIUM * 6 + counts.LOW * 3 + counts.ABSENCE * 8;
  const score = cls === "risk-na" ? null : Math.round(100 * (1 - Math.exp(-raw / 70)));
  const total = flags.length;
  const bar = total ? `<div class="v-bar" aria-hidden="true">${CATEGORIES.filter((c) => counts[c.key])
    .map((c) => `<i style="flex-grow:${counts[c.key]};background:${c.color}"></i>`).join("")}</div>` : "";
  const rows = CATEGORIES.map((c) => {
    const n = counts[c.key];
    const off = state.hidden.has(c.key) ? " off" : "";
    return n
      ? `<tr class="${off.trim()}" data-filter="${c.key}" title="Show or hide ${c.label.toLowerCase()} findings"><td><span class="sw" style="background:${c.color}"></span></td><td>${ROW_LABEL[c.key]}</td><td>${n}</td></tr>`
      : `<tr class="zero"><td><span class="sw" style="background:var(--line-2)"></span></td><td>${ROW_LABEL[c.key]}</td><td>0</td></tr>`;
  }).join("");
  const last = r.decisions.at(-1);
  const decided = last && r.review_status !== "PENDING_REVIEW"
    ? `<div class="decided ${last.decision}">${last.decision === "APPROVED" ? ICONS.check : ICONS.lock}<span><b>${statusLabel(last.decision)}</b> by ${esc(last.officer)} · ${timeAgo(last.created_at)}</span></div>` : "";
  $("#verdict").className = `verdict ${cls}`;
  $("#verdict").innerHTML = `${decided}
    <div class="v-head"><span class="v-label">Risk assessment</span>${score == null ? "" : `<span class="v-score" title="Severity-weighted score"><b>${score}</b> / 100</span>`}</div>
    <div class="v-state"><i></i><h3>${title}</h3></div>
    <p>${sub}</p>
    ${bar}
    <table class="breakdown"><tbody>${rows}</tbody></table>`;
  $("#cFindings").textContent = total || "";
  $("#cPrec").textContent = r.precedents.items.length || "";
}

function banner(kind, icon, html) { return `<div class="banner ${kind}"><span class="bi">${icon}</span><span>${html}</span></div>`; }
function renderBanners() {
  const r = state.review, ins = r.inspection, b = [];
  if (ins.ai_status === "UNAVAILABLE")
    b.push(banner("err", ICONS.warn, "<b>AI inspection unavailable.</b> No AI flags were produced, so review this document manually. Re-run once the service recovers."));
  else if (ins.ai_status === "DEGRADED")
    b.push(banner("warn", ICONS.warn, `<b>Partial AI coverage.</b> ${ins.failed_sections.length} section(s) couldn't be analyzed. Review them manually.`));
  if (r.absence.status !== "OK")
    b.push(banner("warn", ICONS.warn, `Missing-disclosure check unavailable (${esc(r.absence.error || r.absence.status)}).`));
  if (ins.blocked_ai_decisions.length)
    b.push(banner("sec", ICONS.shield, `<b>Blocked ${ins.blocked_ai_decisions.length} attempt${ins.blocked_ai_decisions.length === 1 ? "" : "s"} by the AI to set a decision</b> (${ins.blocked_ai_decisions.map((x) => esc(`${x.key}=${x.value}`)).join(", ")}). Only you can approve or reject.`));
  else if (r.security.prompt_injection.length)
    b.push(banner("sec", ICONS.shield, "<b>Prompt-injection text detected.</b> It was treated as data, not instructions."));
  if (r.security.normalized_characters)
    b.push(banner("sec", ICONS.shield, `Normalized ${r.security.normalized_characters} look-alike or invisible character${r.security.normalized_characters === 1 ? "" : "s"} before analysis.`));
  $("#banners").innerHTML = b.join("");
}

function renderDocument() {
  const text = state.review.masked_text;
  // Absence "closest passage" highlights show only when their card is focused.
  const ranges = allFlags().filter((f) => f.start != null && (f.type !== "absence" || state.focus === f.id));
  const pts = new Set([0, text.length]);
  ranges.forEach((f) => { pts.add(f.start); pts.add(f.end); });
  const bounds = [...pts].sort((a, b) => a - b);
  let html = "";
  for (let i = 0; i < bounds.length - 1; i++) {
    const s = bounds[i], e = bounds[i + 1];
    const seg = text.slice(s, e);
    const cover = ranges.filter((f) => f.start <= s && f.end >= e);
    if (!cover.length) { html += renderText(seg, s); continue; }
    const v = cover.filter((f) => f.type === "violation").sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])[0];
    const sec = cover.find((f) => f.type === "security");
    const cls = sec ? "sec" : v ? `v-${v.severity}` : "abs";
    const focus = cover.some((f) => f.id === state.focus) ? " focus" : "";
    const dim = cover.every((f) => state.hidden.has(category(f))) ? " dim" : "";
    html += `<mark class="${cls}${focus}${dim}" data-ids="${esc(cover.map((f) => f.id).join(" "))}">${renderText(seg, s)}</mark>`;
  }
  $("#docText").innerHTML = html;
  renderRail();
}

function renderRail() {
  const doc = $("#docText"), rail = $("#rail");
  const h = doc.offsetHeight || 1;
  const seen = new Set();
  rail.innerHTML = $$("#docText mark").map((m) => {
    const id = m.dataset.ids.split(" ")[0];
    if (seen.has(id)) return "";
    seen.add(id);
    const f = allFlags().find((x) => x.id === id);
    if (!f || state.hidden.has(category(f))) return "";
    const top = Math.min(98, ((m.offsetTop - doc.offsetTop) / h) * 100);
    const cls = f.type === "security" ? "sec" : f.type === "absence" ? "abs" : f.severity;
    return `<i class="${cls}" style="top:${top}%" data-jump="${esc(id)}" title="${esc(f.rule_id || "Prompt injection")}"></i>`;
  }).join("");
}

function sectionName(pos) {
  const secs = state.review?.inspection.sections || [];
  const s = secs.find((x) => pos >= x.start && pos < x.end) || secs.filter((x) => x.start <= pos).at(-1);
  if (!s) return "";
  if (!s.heading) return `Section ${s.index + 1}`;
  const h = s.heading.replace(/[:.]$/, "").toLowerCase();
  return h.charAt(0).toUpperCase() + h.slice(1);
}
function flagCard(f) {
  const active = f.id === state.focus ? " active" : "";
  const quote = f.start != null ? renderText(state.review.masked_text.slice(f.start, f.end), f.start) : "";
  if (f.type === "absence") {
    const pct = Math.min(100, f.semantic_distance * 100), thr = f.threshold * 100;
    return `<div class="flag absence${active}" data-id="${f.id}" tabindex="0">
      <div class="top"><span class="rid">${esc(f.rule_id)}</span><span class="sev ${f.severity}">${f.severity}</span></div>
      <div class="title">Missing: ${esc(f.rule_title)}</div>
      <div class="reason">${esc(f.rule_text)}</div>
      ${quote ? `<blockquote title="Closest text found">${quote}</blockquote>` : ""}
      <div class="meter" title="Semantic distance ${f.semantic_distance}. Counted as present at ≤ ${f.threshold}."><i style="width:${pct}%"></i><em style="left:${thr}%"></em></div>
      <div class="foot"><span>Distance <b>${f.semantic_distance}</b> (needs ≤ ${f.threshold})</span><span>Click to show the closest text</span></div>
    </div>`;
  }
  if (f.type === "security") {
    return `<div class="flag sec${active}" data-id="${f.id}" tabindex="0">
      <div class="top"><span class="rid">PROMPT-INJECTION</span><span class="sev SEC">SECURITY</span></div>
      <div class="title">Instruction aimed at the AI</div>
      <div class="reason">${esc(f.message)}</div><blockquote>${quote}</blockquote></div>`;
  }
  return `<div class="flag ${f.severity}${active}" data-id="${f.id}" tabindex="0">
    <div class="top"><span class="rid">${esc(f.rule_id)}</span><span class="sev ${f.severity}">${f.severity}</span></div>
    <div class="title">${esc(f.rule_title)}</div>
    <div class="reason">${renderText(f.reason)}</div>
    <blockquote>${quote}</blockquote>
    <div class="foot"><span class="loc">${esc(sectionName(f.start))}</span><span class="num">chars ${f.start}–${f.end}</span><span class="ok-tag" title="The quote appears word for word in the document">Quote verified</span>${f.model_severity_overridden ? `<span title="The model said ${esc(f.model_severity_overridden)}; the rule's severity is used.">severity set by rule</span>` : ""}</div>
  </div>`;
}

function group(title, count, body, open = true) {
  return `<details class="group" ${open ? "open" : ""}><summary>${title} <span class="count">${count}</span></summary><div class="items">${body}</div></details>`;
}
function renderFindings() {
  const r = state.review, ins = r.inspection;
  const vis = (f) => !state.hidden.has(category(f));
  const sec = allFlags().filter((f) => f.type === "security" && vis(f));
  const v = ins.flags.filter(vis).sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.start - b.start);
  const abs = r.absence.flags.filter(vis);
  const present = r.absence.checks.filter((c) => c.present);
  let html = "";
  if (sec.length) html += group("Security", sec.length, sec.map(flagCard).join(""));
  html += group("Rule violations", v.length, v.map(flagCard).join("") ||
    `<div class="none">${ins.flags.length ? "Hidden by filter." : ins.ai_status === "UNAVAILABLE" ? "AI unavailable. No automated flags." : "No grounded violations found."}</div>`);
  html += group("Missing disclosures", abs.length, abs.map(flagCard).join("") || `<div class="none">${r.absence.flags.length ? "Hidden by filter." : "All required disclosures found."}</div>`);
  if (present.length)
    html += group("Disclosures present", present.length, present.map((c) =>
      `<div class="present"><span>✓ ${esc(c.disclosure_id)} · ${esc(c.title)}</span><span>dist ${c.semantic_distance}</span></div>`).join(""), false);
  if (ins.discarded.length)
    html += group("Discarded by validator", ins.discarded.length,
      `<p class="muted small" style="margin:0">These AI flags weren't grounded in the source text, so they were never shown as findings.</p>
       <ul class="discard-list">${ins.discarded.map((d) => `<li><code>${esc(d.reason.replaceAll("_", " "))}</code> · ${esc(d.rule_id || "?")}<div class="q">“${renderText(d.passage || "")}”</div></li>`).join("")}</ul>`, false);
  $("#findings").innerHTML = html;
}

function renderPrecedents() {
  const p = state.review.precedents;
  let html = `<div class="ro"><span>${ICONS.lock}</span><span>Read-only context from past officer decisions. Shown to you only. <b>Never sent to the AI</b> or used in flag detection.</span></div>`;
  if (p.status !== "OK") html += banner("warn", ICONS.warn, `Precedent lookup ${esc(p.status.toLowerCase())}.`);
  html += p.items.map((x) => `
    <div class="prec">
      <div class="hdr"><div><b>${esc(x.title)}</b><div class="small muted">${esc(x.id)} · ${esc(DOC_TYPE_LABEL[x.doc_type] || x.doc_type)}</div></div><span class="status ${x.decision}">${x.decision}</span></div>
      <p class="notes">“${esc(x.notes)}”</p>
      <div class="small muted" style="margin-top:6px">${esc(x.officer)} · ${esc(x.decided_on)}</div>
      <div class="sim"><span>Similarity</span><div class="meter"><i style="width:${Math.round(x.similarity * 100)}%"></i></div><b>${Math.round(x.similarity * 100)}%</b></div>
    </div>`).join("");
  $("#tab-precedents").innerHTML = html;
}

function renderDecisions() {
  const d = state.review.decisions.at(-1);
  $("#lastDecision").innerHTML = d
    ? `<div class="decision-rec"><span><span class="status ${d.decision}">${statusLabel(d.decision)}</span> by <b>${esc(d.officer)}</b> · ${timeAgo(d.created_at)}</span>${d.notes ? `<span class="muted">${renderText(d.notes)}</span>` : ""}</div>`
    : "";
}

async function renderAudit() {
  if (!state.docId) return;
  const rows = await api(`/api/documents/${state.docId}/audit`);
  const label = { ingested: "Document ingested & masked", ai_inspection: "AI inspection run", pii_rehydrated: "PII rehydrated for officer",
    human_decision: "Officer decision", blocked_ai_decision_attempt: "Blocked AI decision attempt" };
  $("#tab-audit").innerHTML = `<div class="timeline">${rows.map((r) => {
    const cls = r.event === "human_decision" ? "human" : r.event.startsWith("blocked") ? "blocked" : "";
    return `<div class="tl ${cls}"><b>${esc(label[r.event] || r.event)}</b><span class="t">${new Date(r.created_at * 1000).toLocaleTimeString()}</span><code>${esc(r.detail)}</code></div>`;
  }).join("")}</div>`;
}

async function renderPayloads() {
  const d = await api("/api/dev/payloads");
  $("#leakBadge").innerHTML = `<div class="leak ${d.raw_pii_hits_all ? "bad" : "ok"}">${d.raw_pii_hits_all ? ICONS.warn : ICONS.shield}
    ${d.raw_pii_hits_all} raw PII values in ${d.total_payloads} outbound payloads <span class="muted small" style="font-weight:400">(${d.known_pii_values} known values checked)</span></div>`;
  $("#payloads").innerHTML = d.items.map((p) => `
    <details class="payload"><summary><code>POST ${esc(p.endpoint)}</code><span class="muted">${p.bytes.toLocaleString()} B · ${p.raw_pii_hits ? "⚠ " + p.raw_pii_hits + " PII" : "clean"}</span></summary>
    <pre>${esc(JSON.stringify(p.payload, null, 2))}</pre></details>`).join("");
}
async function loadFault() {
  const f = await api("/api/dev/fault");
  $("#faultMode").disabled = $("#hallu").disabled = !f.supported;
  if (!f.supported) { $("#halluVal").textContent = "n/a (real LLM provider)"; return; }
  $("#faultMode").value = f.mode;
  $("#hallu").value = f.hallucination_rate;
  $("#halluVal").textContent = Math.round(f.hallucination_rate * 100) + "%";
}

// ----------------------------------------------------------------- focus
function focusFlag(id, { scrollDoc = true, scrollCard = true } = {}) {
  state.focus = id;
  renderDocument();
  $$(".flag").forEach((c) => c.classList.toggle("active", c.dataset.id === id));
  if (scrollDoc) $("#docText mark.focus")?.scrollIntoView({ behavior: "smooth", block: "center" });
  if (scrollCard) {
    switchTab("findings");
    const card = document.querySelector(`.flag[data-id="${CSS.escape(id)}"]`);
    card?.closest("details")?.setAttribute("open", "");
    card?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}
function stepFlag(dir) {
  if (!state.review) return;
  const list = visibleFlags().filter((f) => f.start != null).sort((a, b) => a.start - b.start);
  if (!list.length) return;
  const i = list.findIndex((f) => f.id === state.focus);
  const next = list[(i + dir + list.length) % list.length];
  focusFlag(next.id);
}

// ----------------------------------------------------------------- events
document.addEventListener("click", async (e) => {
  const t = e.target;
  const sample = t.closest("[data-sample]");
  if (sample) return ingestSample(sample.dataset.sample);
  const li = t.closest("#queue li[data-id]");
  if (li) { showLoading(); return openDoc(li.dataset.id); }
  const jump = t.closest("[data-jump]");
  if (jump) return focusFlag(jump.dataset.jump);
  const filter = t.closest("[data-filter]");
  if (filter) {
    const k = filter.dataset.filter;
    state.hidden.has(k) ? state.hidden.delete(k) : state.hidden.add(k);
    renderVerdict(); renderDocument(); renderFindings();
    return;
  }
  const card = t.closest(".flag[data-id]");
  if (card) return focusFlag(card.dataset.id, { scrollCard: false });
  const mark = t.closest("mark[data-ids]");
  if (mark) return focusFlag(mark.dataset.ids.split(" ")[0], { scrollDoc: false });
  const view = t.closest(".seg [data-view]");
  if (view) { state.masked = view.dataset.view === "masked"; if (state.review) render(); loadQueue(); return; }
  const dec = t.closest("[data-decision]");
  if (dec) return decide(dec.dataset.decision, dec);
  const tab = t.closest(".tabs button");
  if (tab) switchTab(tab.dataset.tab);
});

// Approving a document with critical or security findings takes a second, deliberate click.
let confirmTimer = null;
function resetConfirm() {
  clearTimeout(confirmTimer);
  const b = $('[data-decision="APPROVED"]');
  if (b?.dataset.armed) { delete b.dataset.armed; b.lastChild.textContent = " Approve"; b.classList.remove("armed"); }
}
function needsConfirm() {
  return allFlags().some((f) => f.type === "security" || (f.type === "violation" && f.severity === "CRITICAL"));
}

async function decide(decision, btn) {
  if (!state.docId || !state.review) return;
  if (decision === "APPROVED" && needsConfirm() && !btn.dataset.armed) {
    btn.dataset.armed = "1"; btn.classList.add("armed");
    btn.lastChild.textContent = " Approve anyway?";
    confirmTimer = setTimeout(resetConfirm, 4000);
    return toast("This document has critical findings. Click again to approve anyway.");
  }
  resetConfirm();
  btn.disabled = true;
  try {
    await api(`/api/documents/${state.docId}/decision`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decision, notes: $("#notes").value }),
    });
    $("#notes").value = "";
    toast(`${decision === "APPROVED" ? "Approved" : "Rejected"} by ${officer()}`);
    state.review = await api(`/api/documents/${state.docId}/analyze`, { method: "POST" });
    render(); loadQueue();
  } catch (err) { toast(err.message); } finally { btn.disabled = false; }
}

document.addEventListener("mouseover", (e) => {
  const mark = e.target.closest?.("mark[data-ids]");
  const tip = $("#tip");
  if (!mark || !state.review) { tip.hidden = true; return; }
  const ids = mark.dataset.ids.split(" ");
  const flags = allFlags().filter((f) => ids.includes(f.id));
  tip.innerHTML = flags.map((f) => f.type === "security"
    ? `<div><span class="rid">PROMPT-INJECTION</span><span class="sev SEC">SECURITY</span><div class="r">Instruction aimed at the AI. Treated as data.</div></div>`
    : `<div style="margin-bottom:4px"><span class="rid">${esc(f.rule_id)}</span><span class="sev ${f.severity}">${f.severity}</span><div class="r">${esc(f.type === "absence" ? "Closest text to missing: " + f.rule_title : f.rule_title + ": " + f.reason)}</div></div>`).join("");
  const r = mark.getBoundingClientRect();
  tip.hidden = false;
  const tw = tip.offsetWidth, th = tip.offsetHeight;
  tip.style.left = Math.max(8, Math.min(window.innerWidth - tw - 8, e.clientX - tw / 2)) + "px";
  tip.style.top = (r.top - th - 8 > 8 ? r.top - th - 8 : r.bottom + 8) + "px";
});
$("#center").addEventListener("scroll", () => ($("#tip").hidden = true));

document.addEventListener("keydown", (e) => {
  if (e.target.closest?.("input, textarea, select")) return;
  if (e.key === "j" || e.key === "ArrowDown" && e.altKey) { e.preventDefault(); stepFlag(1); }
  else if (e.key === "k" || e.key === "ArrowUp" && e.altKey) { e.preventDefault(); stepFlag(-1); }
  else if (e.key === "Escape" && state.focus) { state.focus = null; renderDocument(); $$(".flag.active").forEach((c) => c.classList.remove("active")); }
  else if (e.key === "Enter" && e.target.matches(".flag[data-id]")) focusFlag(e.target.dataset.id, { scrollCard: false });
});

function switchTab(name) {
  $$(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  $$(".tab").forEach((t) => (t.hidden = t.id !== `tab-${name}`));
  if (name === "audit") renderAudit().catch(quiet);
  if (name === "dev") { renderPayloads().catch(quiet); loadFault().catch(quiet); }
}

$("#rerun").onclick = () => { if (state.docId) { showLoading(); openDoc(state.docId, true); } };
$("#tryDemo").onclick = () => ingestSample("Investment_Agreement_Jane_Smith.txt");
$("#fileInput").onchange = (e) => { e.target.files[0] && uploadFile(e.target.files[0]); e.target.value = ""; };
for (const dz of [$("#dropzone"), $("#dropTarget")]) {
  ["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); }));
  ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, () => dz.classList.remove("drag")));
  dz.addEventListener("drop", (e) => { e.preventDefault(); e.dataTransfer.files[0] && uploadFile(e.dataTransfer.files[0]); });
}
// Rail ticks are positioned from real layout, so recompute when fonts load or the page reflows.
new ResizeObserver(() => state.review && !$("#docView").hidden && renderRail()).observe($("#docText"));
document.fonts?.ready.then(() => state.review && renderRail());
$("#refreshPayloads").onclick = () => renderPayloads().catch(quiet);
const postFault = (body) => api("/api/dev/fault", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
$("#faultMode").onchange = (e) => postFault({ mode: e.target.value })
  .then(() => toast(`Mock LLM: ${e.target.selectedOptions[0].text}. Re-run to see the effect.`)).catch(quiet);
$("#hallu").oninput = (e) => ($("#halluVal").textContent = Math.round(e.target.value * 100) + "%");
$("#hallu").onchange = (e) => postFault({ mode: $("#faultMode").value, hallucination_rate: +e.target.value }).catch(quiet);

// ------------------------------------------------------------- session
function initials(name) {
  const n = (name || "").replace(/^officer\s+/i, "").trim();
  return n ? n.split(/\s+/).map((w) => w[0]).join("").slice(0, 2).toUpperCase() : "?";
}
function setUser(user) {
  state.user = user;
  $("#userMenu").hidden = !user;
  if (!user) return;
  $("#avatar").textContent = initials(user.display_name);
  $("#userName").textContent = user.display_name;
  $("#userRole").textContent = user.role;
  $("#deleteDoc").hidden = user.role !== "admin";
}
function resetWorkspace() {
  stageTimers.forEach(clearTimeout);
  Object.assign(state, { docId: null, review: null, vault: null, focus: null, hidden: new Set() });
  resetConfirm();
  for (const sel of ["#docText", "#findings", "#verdict", "#banners", "#rail", "#docMeta", "#lastDecision",
    "#tab-precedents", "#tab-audit", "#payloads", "#leakBadge"]) $(sel).innerHTML = "";
  $("#docTitle").textContent = "";
  $("#notes").value = "";
  $("#tip").hidden = true;
  $("#empty").hidden = false; $("#docView").hidden = true; $("#rightPane").hidden = true;
  switchTab("findings");
}
function showLogin(message = "") {
  setUser(null);
  // Remove the previous officer's view, including rehydrated client PII, from the DOM.
  resetWorkspace();
  $("#queue").innerHTML = ""; $("#samples").innerHTML = ""; $("#queueCount").textContent = "";
  $("#login").hidden = false;
  $(".layout").inert = true;  // keep keyboard/screen-reader focus inside the sign-in dialog
  $("#loginError").hidden = !message;
  $("#loginError").textContent = message;
  const demo = state.health?.demo_login;
  $("#demoHint").hidden = !demo;
  if (demo) $("#demoHint").innerHTML = `Demo account: <code>${esc(demo.username)}</code> / <code>${esc(demo.password)}</code>
    <button type="button" id="fillDemo">Use it</button>`;
  setTimeout(() => $("#loginUser").focus(), 0);
}
async function startApp(user) {
  setUser(user);
  $("#login").hidden = true;
  $(".layout").inert = false;
  resetWorkspace();
  if (!state.health?.dev_tools) $("#devTabBtn").hidden = true;
  await Promise.all([loadSamples(), loadQueue()]);
}
$("#loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#loginBtn");
  btn.disabled = true; $("#loginError").hidden = true;
  try {
    const user = await api("/api/auth/login", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: $("#loginUser").value, password: $("#loginPass").value }),
    });
    $("#loginPass").value = "";
    await startApp(user);
  } catch (err) {
    $("#loginError").textContent = err.message.replace(/^\d+\s/, "");
    $("#loginError").hidden = false;
  } finally { btn.disabled = false; }
});
document.addEventListener("click", (e) => {
  if (e.target.id !== "fillDemo") return;
  const d = state.health.demo_login;
  $("#loginUser").value = d.username; $("#loginPass").value = d.password;
  $("#loginForm").requestSubmit();
});
$("#logoutBtn").onclick = async () => {
  try { await api("/api/auth/logout", { method: "POST" }); } catch {}
  showLogin();
};
$("#deleteDoc").onclick = async () => {
  if (!state.docId) return;
  if (!confirm("Delete this document? Its PII vault is destroyed (crypto-shredded) and cannot be recovered. Decisions and the audit trail are kept.")) return;
  try {
    await api(`/api/documents/${state.docId}`, { method: "DELETE" });
    toast("Document deleted and PII crypto-shredded");
    resetWorkspace();
    loadQueue();
  } catch (err) { toast(err.message); }
};

// theme
const savedTheme = load("theme");
if (savedTheme) document.documentElement.dataset.theme = savedTheme;
$("#themeBtn").onclick = () => {
  const dark = document.documentElement.dataset.theme === "dark";  // light is the default
  document.documentElement.dataset.theme = dark ? "light" : "dark";
  store("theme", document.documentElement.dataset.theme);
};

(async function init() {
  try {
    const h = await api("/api/health");
    state.health = h;
    const row = (k, v) => `<span class="chip">${k}<b title="${esc(v)}">${esc(v)}</b></span>`;
    $("#engineChips").innerHTML = row("PII detection", h.pii_engine) + row("Model", h.model_id) +
      row("Rules", h.rules_version) + (h.env !== "production" ? row("Environment", h.env) : "");
    if (h.max_upload_mb) $("#uploadLimits").textContent = `PDF, DOCX, XLSX, CSV or TXT · up to ${h.max_upload_mb} MB`;
  } catch {}
  try {
    const { user } = await api("/api/auth/session");
    if (user) await startApp(user); else showLogin();
  } catch { showLogin(); }
})();
