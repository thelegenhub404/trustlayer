// TrustLayer frontend. All agent-controlled text is inserted via textContent,
// never as HTML (prompt-injection defense, plan section 11.2).
"use strict";

const LEVEL_BADGE = {
  L0: "Unverified",
  L1: "Domain verified",
  L2: "Identity verified",
  L3: "Reputation",
};

const ICONS = {
  shield: '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg>',
  check: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>',
  x: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg>',
  alert: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4M12 17h.01"/></svg>',
};

function badge(level) {
  const s = document.createElement("span");
  s.className = "badge " + (level || "L0");
  s.innerHTML = ICONS.shield;
  s.appendChild(document.createTextNode(LEVEL_BADGE[level] || "Unverified"));
  s.title = "Trust level " + (level || "L0");
  return s;
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

async function doSearch(ev) {
  ev.preventDefault();
  const q = document.getElementById("q").value.trim();
  const minLevel = document.getElementById("min_level").value;
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (minLevel) params.set("min_level", minLevel);

  const box = document.getElementById("results");
  const list = document.getElementById("results-list");
  const meta = document.getElementById("results-meta");
  box.hidden = false;
  meta.textContent = "Searching…";
  meta.setAttribute("aria-busy", "true");

  let data;
  try {
    const res = await fetch("/v1/search?" + params.toString());
    data = await res.json();
  } catch {
    meta.textContent = "Search failed — the API may be warming up. Try again.";
    meta.setAttribute("aria-busy", "false");
    return false;
  }
  meta.setAttribute("aria-busy", "false");
  meta.textContent =
    `${data.total} agent(s) · index ${data.index_generated_at || "unavailable"}`;

  list.textContent = "";
  if (!data.results || !data.results.length) {
    const empty = el("div", "card");
    empty.appendChild(el("b", null, "No agents matched."));
    empty.appendChild(el("p", null,
      "Try a broader term, lower the minimum level, or publish your own agent: add your domain to seeds.txt in the repository."));
    list.appendChild(empty);
    return false;
  }

  for (const a of data.results) {
    const card = el("div", "card");
    const row = el("div", "title-row");
    const link = el("a", null, a.name || a.domain);
    link.href = "/agent.html?id=" + encodeURIComponent(a.agent_id);
    row.appendChild(link);
    row.appendChild(badge(a.level));
    card.appendChild(row);
    if (a.description) card.appendChild(el("p", null, a.description));
    if (a.trust != null) {
      card.appendChild(el("p", "trust-line",
        `trust ${a.trust} · confidence ${a.confidence}`));
    }
    list.appendChild(card);
  }
  return false;
}

function checkIcon(ok) {
  const s = document.createElement("span");
  s.className = ok ? "ok" : "fail";
  s.innerHTML = ok ? ICONS.check : ICONS.x;
  return s;
}

async function renderAgent() {
  const id = new URLSearchParams(location.search).get("id") || "";
  const root = document.getElementById("agent-root");
  const loading = document.getElementById("agent-loading");

  let res, a;
  try {
    res = await fetch("/v1/agents/" + encodeURIComponent(id));
    a = await res.json();
  } catch {
    loading.textContent = "Could not reach the API. Try again.";
    return;
  }
  loading.remove();

  if (res.status === 404) {
    const card = el("div", "card");
    card.appendChild(el("p", "redflag", "Agent not indexed."));
    card.appendChild(el("p", "muted",
      "It may not be verified yet, or the domain was never added to seeds.txt."));
    root.appendChild(card);
    return;
  }

  const h = el("h1", null, a.name || a.domain);
  h.style.marginBottom = "0.4rem";
  root.appendChild(h);
  const row = el("div", "title-row");
  row.appendChild(badge(a.level));
  root.appendChild(row);
  root.appendChild(el("p", "agent-meta", a.agent_id));
  if (a.description) root.appendChild(el("p", null, a.description));

  if (a.trust != null) {
    const sb = el("div", "scorebox");
    sb.textContent = `trust ${a.trust} · confidence ${a.confidence}`;
    root.appendChild(sb);
  } else if (a.level === "L0" || a.level === "L1") {
    root.appendChild(el("p", "hint", "Unrated: the score requires level L2."));
  }

  root.appendChild(el("h2", null, "Verification"));
  const checks = el("ul", "checks");
  for (const c of a.checks || []) {
    const li = document.createElement("li");
    li.appendChild(checkIcon(c.ok));
    li.appendChild(el("span", "name", c.name));
    if (c.reason) li.appendChild(el("span", "reason", c.reason));
    checks.appendChild(li);
  }
  root.appendChild(checks);

  for (const f of a.red_flags || []) {
    const p = el("p", "redflag", f);
    p.prepend(Object.assign(document.createElement("span"), {
      innerHTML: ICONS.alert, className: "fail",
    }));
    root.appendChild(p);
  }

  if ((a.capabilities || []).length) {
    root.appendChild(el("h2", null, "Capabilities"));
    for (const cap of a.capabilities) {
      const card = el("div", "card");
      const crow = el("div", "title-row");
      crow.appendChild(el("b", null, cap.id));
      if (cap.payment && cap.payment.method) {
        crow.appendChild(el("span", "badge L0", "payment: " + cap.payment.method));
      }
      card.appendChild(crow);
      if (cap.description) card.appendChild(el("p", null, cap.description));
      if (cap.endpoint) card.appendChild(el("p", "agent-meta", cap.endpoint));
      root.appendChild(card);
    }
  }
}
