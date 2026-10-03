// TrustLayer agent page. All agent-controlled text is inserted as textContent,
// never as HTML (prompt-injection defense, plan section 11.2).
"use strict";

(function () {
  var LEVEL_LABEL = { L0: "Unverified", L1: "Domain verified", L2: "Identity verified", L3: "Reputation" };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function badge(level) {
    var b = el("span", "badge " + (level || "L0").toLowerCase());
    b.textContent = LEVEL_LABEL[level] || "Unverified";
    return b;
  }

  function resolveId() {
    // Clean route /agent/did:web:host first; legacy ?id= fallback.
    var seg = "";
    try { seg = decodeURIComponent(location.pathname.split("/").pop() || ""); } catch (e) { seg = ""; }
    if (/^did:web:/i.test(seg)) return seg.toLowerCase();
    return new URLSearchParams(location.search).get("id") || "";
  }

  function renderAgent() {
    var id = resolveId();
    var root = document.getElementById("agent-root");
    var loading = document.getElementById("agent-loading");

    fetch("/v1/agents/" + encodeURIComponent(id))
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
      .then(function (res) {
        loading.remove();
        var a = res.body;
        if (!res.ok) {
          var nf = el("div", "note warn");
          nf.appendChild(el("b", null, "Agent not indexed"));
          nf.appendChild(document.createTextNode(
            "It may not be verified yet, or the domain was never added to seeds.txt."));
          root.appendChild(nf);
          return;
        }

        var h = el("h1", null, a.name || a.domain);
        root.appendChild(h);
        var meta = el("p", "crumb mono", a.agent_id);
        root.appendChild(meta);
        root.appendChild(badge(a.level));
        if (a.description) root.appendChild(el("p", "lead", a.description));

        if (a.trust != null) {
          var sb = el("p", "mono scoreline");
          sb.textContent = "trust " + a.trust + " · confidence " + a.confidence;
          root.appendChild(sb);
        } else if (a.level === "L0" || a.level === "L1") {
          root.appendChild(el("p", "hint", "Unrated: the score requires level L2."));
        }

        root.appendChild(el("h2", null, "Verification"));
        root.appendChild(el("p", null,
          "Run by the crawler against the live domain. Any failure lowers the level."));
        var table = el("table");
        var thead = document.createElement("tr");
        ["Check", "Result"].forEach(function (t) {
          var th = document.createElement("th"); th.textContent = t; thead.appendChild(th);
        });
        table.appendChild(thead);
        (a.checks || []).forEach(function (c) {
          var tr = document.createElement("tr");
          var td1 = document.createElement("td");
          var code = el("code", null, c.name); td1.appendChild(code);
          if (c.reason) td1.appendChild(el("div", "hint", c.reason));
          var td2 = document.createElement("td");
          td2.className = c.ok ? "ok" : "fail";
          td2.textContent = c.ok ? "Passed" : "Failed";
          tr.append(td1, td2);
          table.appendChild(tr);
        });
        root.appendChild(table);

        (a.red_flags || []).forEach(function (f) {
          var n = el("div", "note warn");
          n.appendChild(el("b", null, "Red flag"));
          n.appendChild(document.createTextNode(f));
          root.appendChild(n);
        });

        if ((a.capabilities || []).length) {
          root.appendChild(el("h2", null, "Badge"));
        var note = el("div", "note");
        note.appendChild(el("b", null, "Use this badge on your site"));
        var snippet = el("code", null,
          '<a href="' + location.origin + "/agent/" + a.agent_id + '">' +
          '<img src="' + location.origin + "/badge/" + a.agent_id +
          '" alt="TrustLayer badge"></a>');
        snippet.style.display = "block";
        snippet.style.whiteSpace = "pre-wrap";
        snippet.style.wordBreak = "break-all";
        note.appendChild(snippet);
        note.appendChild(el("p", "hint",
          "The badge only proves what this page shows."));
        root.appendChild(note);

        root.appendChild(el("h2", null, "Capabilities"));
          var ct = el("table");
          var ch = document.createElement("tr");
          ["Capability", "Endpoint", "Payment"].forEach(function (t) {
            var th = document.createElement("th"); th.textContent = t; ch.appendChild(th);
          });
          ct.appendChild(ch);
          a.capabilities.forEach(function (cap) {
            var tr = document.createElement("tr");
            var td1 = document.createElement("td");
            td1.appendChild(el("strong", null, cap.id || ""));
            if (cap.description) td1.appendChild(el("div", "hint", cap.description));
            var td2 = document.createElement("td");
            var code2 = el("code", null, cap.endpoint || "");
            td2.appendChild(code2);
            var td3 = document.createElement("td");
            td3.textContent = (cap.payment && cap.payment.method) || "none";
            tr.append(td1, td2, td3);
            ct.appendChild(tr);
          });
          root.appendChild(ct);
        }
      })
      .catch(function () {
        loading.textContent = "Could not reach the API. Try again in a minute.";
      });
  }

  window.renderAgent = renderAgent;
})();
