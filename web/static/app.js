/* Watchtower frontend. No framework, no build step — open the page and it works.
   The sweep arrives over SSE, so sources fill their lane as each one lands
   rather than everything appearing at once after a minute of nothing. */

const $ = (s) => document.querySelector(s);
const el = (t, cls, txt) => {
  const n = document.createElement(t);
  if (cls) n.className = cls;
  if (txt != null) n.textContent = txt;
  return n;
};

const BAND_COLOUR = {
  HIGH: "var(--high)", MED: "var(--med)", LOW: "var(--low)", WEAK: "var(--weak)",
};
const BAND_SEGMENTS = { HIGH: 5, MED: 4, LOW: 2, WEAK: 1 };

let selected = new Set();
let hours = 72;
let stream = null;

/* ------------------------------------------------------------ bootstrap */

async function init() {
  let data;
  try {
    data = await (await fetch("/api/sources")).json();
  } catch {
    $("#ai-status").textContent = "server unreachable";
    return;
  }

  const box = $("#sources");
  data.sources.forEach((s) => {
    const chip = el("button", "chip", s.name);
    chip.type = "button";
    // Gate on the key actually being present, not on whether the source is a
    // default. opensanctions is both, so the old `needs_key && !default` guard
    // never fired and it shipped selected but dead.
    const usable = s.available !== false;
    const on = s.default && usable;
    chip.setAttribute("aria-pressed", String(on));
    if (on) { chip.classList.add("is-on"); selected.add(s.name); }
    if (!usable) {
      chip.disabled = true;
      chip.title = `Set ${s.key_name || "the API key"} to enable`;
    }
    chip.onclick = () => {
      chip.classList.toggle("is-on");
      const on = chip.classList.contains("is-on");
      chip.setAttribute("aria-pressed", String(on));
      on ? selected.add(s.name) : selected.delete(s.name);
    };
    box.append(chip);
  });

  // On a serverless host the archive lives in /tmp and does not survive between
  // requests. Saying nothing would let someone tick "Keep results", see it
  // succeed, and find an empty Archive tab later — a silent data loss.
  if (data.ephemeral_storage) {
    const keep = $("#keep");
    keep.closest(".toggle").title =
      "This deployment has no persistent disk — saved results are lost between requests.";
    const note = el("p", "hint warn-note",
      "Storage on this host is temporary: anything you keep is lost between requests.");
    $("#sweep-form").append(note);
  }

  if (!data.ai_available) {
    $("#use-ai").checked = false;
    $("#use-ai").disabled = true;
    $("#use-ai").closest(".toggle").title =
      "Set ANTHROPIC_API_KEY to enable relevance scoring";
    $("#ai-status").textContent = "keyword ranking";
  } else {
    $("#ai-status").textContent = "scoring ready";
  }
}

/* -------------------------------------------------------------- controls */

$("#window").onclick = (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  $("#window").querySelectorAll("button").forEach((x) => {
    x.classList.remove("is-on");
    x.setAttribute("aria-checked", "false");
  });
  b.classList.add("is-on");
  b.setAttribute("aria-checked", "true");
  hours = Number(b.dataset.h);
};

document.querySelectorAll(".tab").forEach((tab) => {
  tab.onclick = () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("is-on"));
    tab.classList.add("is-on");
    $("#view-sweep").hidden = tab.dataset.view !== "sweep";
    $("#view-archive").hidden = tab.dataset.view !== "archive";
  };
});

/* ----------------------------------------------------------------- sweep */

$("#sweep-form").onsubmit = (e) => {
  e.preventDefault();
  const q = $("#q").value.trim();
  if (q.length < 2) return;
  if (!selected.size) return showEmpty("Pick a source", "Nothing is selected to search.");
  startSweep(q);
};

function startSweep(q) {
  if (stream) stream.close();

  $("#go").disabled = true;
  $("#go").textContent = "Sweeping";
  $("#results").hidden = true;
  $("#empty").hidden = true;
  $("#trace").hidden = false;
  $("#trace-title").textContent = `Sweeping "${q}"`;
  $("#trace-stage").textContent = "";

  const lanes = $("#lanes");
  lanes.replaceChildren();
  const laneOf = {};
  [...selected].forEach((name) => {
    const lane = el("div", "lane pending");
    lane.append(el("span", "lane-name", name));
    const bar = el("div", "lane-bar");
    bar.append(el("div", "lane-fill"));
    lane.append(bar, el("span", "lane-count", "·"));
    lanes.append(lane);
    laneOf[name] = lane;
  });

  const params = new URLSearchParams({
    q, hours,
    sources: [...selected].join(","),
    use_ai: $("#use-ai").checked,
    fetch_bodies: $("#fetch-bodies").checked,
    // Off by default, same as the API. The Archive tab is empty until this is
    // ticked, so it's the only way to populate it from the browser.
    save: $("#keep").checked,
  });

  stream = new EventSource(`/api/sweep?${params}`);

  stream.addEventListener("source", (ev) => {
    const d = JSON.parse(ev.data);
    const lane = laneOf[d.name];
    if (!lane) return;
    lane.classList.remove("pending");
    lane.classList.add("done");
    if (d.error) lane.classList.add("failed");
    if (d.skipped) lane.classList.add("skipped");
    if (!d.count) lane.classList.add("zero");
    // Bars are relative to 20 hits, capped — absolute scale would make a
    // 3-hit source look like a failure next to a 60-hit one.
    lane.style.setProperty("--w", `${Math.min(100, (d.count / 20) * 100) || 4}%`);
    // A failed or unsearched lane must never read as "0". Zero is a finding.
    lane.querySelector(".lane-count").textContent =
      d.error ? "failed" : d.skipped ? "off" : d.count;
    if (d.reason || d.skipped) lane.title = d.reason || d.skipped;
  });

  stream.addEventListener("stage", (ev) => {
    const d = JSON.parse(ev.data);
    const label = {
      dedupe: `deduped ${d.before} → ${d.after}`,
      fetch: `reading ${d.count} article${d.count === 1 ? "" : "s"}`,
      score: `scoring ${d.count}`,
    }[d.stage];
    if (label) $("#trace-stage").textContent = label;
  });

  stream.addEventListener("scored", (ev) => {
    const d = JSON.parse(ev.data);
    $("#trace-stage").textContent = `scored [${d.relevance}] ${d.title}`;
  });

  stream.addEventListener("done", (ev) => {
    finish();
    render(JSON.parse(ev.data));
  });

  stream.addEventListener("failed", (ev) => {
    finish();
    showEmpty("The sweep stopped", JSON.parse(ev.data).message);
  });

  stream.onerror = () => {
    if (!$("#go").disabled) return;   // already finished cleanly
    finish();
    showEmpty("Lost the connection", "The server closed the stream. Check its log and try again.");
  };
}

function finish() {
  if (stream) { stream.close(); stream = null; }
  $("#go").disabled = false;
  $("#go").textContent = "Sweep";
  $("#trace-stage").textContent = "";
  $("#trace-title").textContent = "Sources";
}

/* --------------------------------------------------------------- render */

function gauge(band) {
  const g = el("span", "gauge");
  const on = BAND_SEGMENTS[band] || 1;
  for (let i = 0; i < 5; i++) g.append(el("i", i < on ? "on" : ""));
  return g;
}

function card(item) {
  const c = el("article", "card");
  c.style.setProperty("--band", BAND_COLOUR[item.band] || "var(--weak)");

  const top = el("div", "card-top");
  top.append(gauge(item.band), el("span", "score", item.relevance));
  c.append(top);

  const h = el("h3");
  const a = el("a", null, item.title || "(untitled)");
  a.href = item.url;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  h.append(a);
  c.append(h);

  // How many independent domains carried this story. The cheapest strong
  // signal that something is real, and it would otherwise be thrown away by
  // dedupe — so it gets its own badge rather than hiding in the metadata line.
  const corroboration = item.raw_meta?.corroboration || 1;
  if (corroboration > 1) {
    const c = el("span", "corrob", `${corroboration} sources`);
    c.title = (item.raw_meta.corroborating_domains || []).join("\n");
    top.append(c);
  }
  if (item.raw_meta?.headline_only) {
    const h = el("span", "flag", "headline only");
    h.title = "No article body was read — scored on the headline alone.";
    top.append(h);
  }

  const meta = el("p", "card-meta");
  meta.append(el("span", null, item.source));
  if (item.published_at) meta.append(el("span", null, item.published_at.slice(0, 16)));
  if (item.author) meta.append(el("span", null, item.author));
  try { meta.append(el("span", null, new URL(item.url).hostname)); } catch {}
  c.append(meta);

  const body = item.summary || item.text;
  if (body) c.append(el("p", "body", body.slice(0, 320)));

  if (item.categories?.length) {
    const tags = el("div", "tags");
    item.categories.forEach((t) => tags.append(el("span", "tag", t)));
    c.append(tags);
  }
  return c;
}

/* Why a count can't be trusted, in the user's words rather than a stack trace. */
function coverageNotes(d) {
  return [
    ...Object.entries(d.failed || {}).map(([k, v]) => `${k} failed — ${v}`),
    ...Object.entries(d.skipped || {}).map(([k, v]) => `${k} was not searched — ${v}`),
  ];
}

function render(d) {
  const notes = coverageNotes(d);

  if (!d.items.length) {
    // "Nothing came back" is a claim about the world. Only make it when every
    // source actually answered; otherwise this is an absence of evidence that
    // someone could mistake for evidence of absence.
    return d.complete === false
      ? showEmpty(
          "Incomplete sweep — no results",
          "This is not a clean result. Some sources could not be searched, so " +
          "nothing here rules anything out.",
          notes)
      : showEmpty(
          "Nothing came back",
          "Every source was searched and none returned a match. Try a longer " +
          "window, fewer words, or looser terms.",
          notes);
  }

  const strong = d.items.filter((i) => i.relevance >= 60).length;
  const sum = $("#summary");
  sum.replaceChildren();
  // Results arrived, but not from everywhere. Say so next to the count, or the
  // count reads as the whole picture.
  if (d.complete === false) {
    const w = el("span", "warn",
      `partial coverage — ${notes.length} source${notes.length === 1 ? "" : "s"} unavailable`);
    w.title = notes.join("\n");
    sum.append(w);
  }
  const n = el("span");
  n.innerHTML = `<strong>${d.items.length}</strong> result${d.items.length === 1 ? "" : "s"}`;
  sum.append(n);
  if (d.enriched) {
    const s = el("span");
    s.innerHTML = `<strong>${strong}</strong> scored 60+`;
    sum.append(s);
  } else {
    sum.append(el("span", null,
      `keyword ranking — ${d.scoring_error || "no API key"}`));
  }
  if (d.report) {
    const link = el("a", null, "Download report");
    link.href = `/api/report/${encodeURIComponent(d.report)}`;
    sum.append(link);
  }

  $("#findings").replaceChildren(...d.items.map(card));

  const side = $("#side");
  side.replaceChildren();

  if (d.entities.length) {
    const p = el("div", "panel");
    p.append(el("h4", null, "Recurring names"));
    const ul = el("ul");
    d.entities.slice(0, 12).forEach((e) => {
      const li = el("li");
      li.append(el("span", null, e.name), el("span", null, e.count));
      ul.append(li);
    });
    p.append(ul);
    side.append(p);
  }

  const p2 = el("div", "panel");
  p2.append(el("h4", null, "Source yield"));
  const ul2 = el("ul");
  Object.entries(d.per_source).forEach(([k, v]) => {
    const li = el("li");
    li.append(el("span", null, k), el("span", null, v));
    ul2.append(li);
  });
  p2.append(ul2);
  side.append(p2);

  if (d.errors.length) {
    const p3 = el("div", "panel");
    p3.append(el("h4", null, "Problems"));
    d.errors.slice(0, 6).forEach((e) => p3.append(el("p", "errs", e)));
    side.append(p3);
  }

  $("#results").hidden = false;
  $("#empty").hidden = true;
}

function showEmpty(title, msg, errors) {
  const box = $("#empty");
  box.replaceChildren(el("h3", null, title), el("p", null, msg));
  // A zero-result sweep is more often a broken source than an absent story.
  // The Problems panel lives in #results, which this hides — so without this
  // the reason a source failed is only ever in the server log.
  if (errors && errors.length) {
    const box2 = el("div", "empty-errs");
    box2.append(el("h4", null, "What went wrong"));
    errors.slice(0, 6).forEach((e) => box2.append(el("p", "errs", e)));
    box.append(box2);
  }
  box.hidden = false;
  $("#results").hidden = true;
}

/* --------------------------------------------------------------- archive */

$("#archive-form").onsubmit = async (e) => {
  e.preventDefault();
  const q = $("#aq").value.trim();
  if (!q) return;
  const out = $("#archive-results");
  out.replaceChildren(el("p", "hint", "Searching…"));
  try {
    const r = await fetch(`/api/archive?q=${encodeURIComponent(q)}`);
    if (!r.ok) {
      const err = await r.json();
      out.replaceChildren(el("p", "errs", err.detail || "Search failed"));
      return;
    }
    const d = await r.json();
    out.replaceChildren(
      ...(d.items.length
        ? d.items.map(card)
        : [el("p", "hint", "Nothing saved matches that. Tick “Keep results” on the Sweep tab to start filling the archive.")])
    );
  } catch {
    out.replaceChildren(el("p", "errs", "Could not reach the server."));
  }
};

init();
