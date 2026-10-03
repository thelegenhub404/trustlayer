// TrustLayer frontend. All agent-controlled text is inserted as textContent,
// never as HTML (prompt injection defense, plan section 11.2).
"use strict";

const LEVEL_BADGE = { L0: "Unverified", L1: "Domain verified", L2: "Identity verified", L3: "Reputation" };

function badge(level) {
  const s = document.createElement("span");
  s.className = "badge " + (level || "L0");
  s.textContent = LEVEL_BADGE[level] || "Unverified";
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
  const res = await fetch("/v1/search?" + params.toString());
  const data = await res.json();
  const box = document.getElementById("results");
  const list = document.getElementById("results-list");
  list.textContent = "";
  document.getElementById("results-meta").textContent =
    `${data.total} agent(s) · index ${data.index_generated_at || "n/a"}`;
  if (!data.results || !data.results.length) {
    list.appendChild(el("p", "muted", "No agents matched."));
  }
  for (const a of data.results) {
    const card = el("div", "card");
    const link = el("a", null, a.name || a.domain);
    link.href = "/agent.html?id=" + encodeURIComponent(a.agent_id);
    card.appendChild(link);
    card.appendChild(document.createTextNode(" "));
    card.appendChild(badge(a.level));
    if (a.description) card.appendChild(el("p", "muted", a.description));
    if (a.trust != null) {
      card.appendChild(el("p", null,
        `trust ${a.trust} · confidence ${a.confidence}`));
    }
    list.appendChild(card);
  }
  box.hidden = false;
  return false;
}

async function renderAgent() {
  const id = new URLSearchParams(location.search).get("id") || "";
  const root = document.getElementById("agent-root");
  const res = await fetch("/v1/agents/" + encodeURIComponent(id));
  if (res.status === 404) {
    root.textContent = "";
    root.appendChild(el("p", "redflag", "Agent not indexed."));
    return;
  }
  const a = await res.json();
  root.textContent = "";
  const h = el("h1", null, a.name || a.domain);
  root.appendChild(h);
  root.appendChild(badge(a.level));
  root.appendChild(el("p", "muted", a.agent_id));
  if (a.description) root.appendChild(el("p", null, a.description));

  if (a.trust != null) {
    root.appendChild(el("p", null, `trust ${a.trust} · confidence ${a.confidence}`));
  } else if (a.level === "L0" || a.level === "L1") {
    root.appendChild(el("p", "muted", "Unrated: score requires level L2."));
  }

  const checks = el("ul", "checks");
  for (const c of a.checks || []) {
    const li = el("li", c.ok ? "ok" : "fail",
      (c.ok ? "✓ " : "✗ ") + c.name + (c.reason ? " — " + c.reason : ""));
    checks.appendChild(li);
  }
  root.appendChild(el("h2", null, "Verification"));
  root.appendChild(checks);

  for (const f of a.red_flags || []) {
    root.appendChild(el("p", "redflag", "⚠ " + f));
  }

  if ((a.capabilities || []).length) {
    root.appendChild(el("h2", null, "Capabilities"));
    for (const cap of a.capabilities) {
      const card = el("div", "card");
      card.appendChild(el("b", null, cap.id));
      if (cap.description) card.appendChild(el("p", null, cap.description));
      if (cap.endpoint) card.appendChild(el("p", "muted", cap.endpoint));
      root.appendChild(card);
    }
  }
}
