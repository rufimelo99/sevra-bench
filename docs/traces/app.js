(() => {
  const app = document.getElementById('app');
  const cache = {};
  let manifest, index;

  // All text is inserted via textContent: PR bodies and model output are untrusted.
  const h = (tag, attrs, ...kids) => {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) el.setAttribute(k, v);
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return el;
  };
  const show = (...kids) => app.replaceChildren(...kids.flat(Infinity).filter((k) => k != null && k !== false));
  const fetchJSON = async (p) => (cache[p] ??= await (await fetch(p)).json());
  const label = (m) => manifest.models[m] || m;
  const nice = (s) => (s || '').replace(/_/g, ' ');
  const cweNum = (c) => c.replace('cwe', 'CWE-');

  // theme
  const root = document.documentElement;
  try { const t = localStorage.getItem('theme'); if (t) root.dataset.theme = t; } catch (e) {}
  document.getElementById('theme').onclick = () => {
    const dark = root.dataset.theme === 'dark' || (!root.dataset.theme && matchMedia('(prefers-color-scheme: dark)').matches);
    root.dataset.theme = dark ? 'light' : 'dark';
    try { localStorage.setItem('theme', root.dataset.theme); } catch (e) {}
  };

  const filters = { cwe: '', framing: '', model: '', outcome: '', q: '' };
  let sortKey = 'cwe', sortDir = 1;

  const blockedCount = (r) => Object.values(r.verdicts).filter(Boolean).length;
  const dots = (r) => h('span', { class: 'dots' }, Object.keys(manifest.models).map((m) =>
    h('span', { class: 'dot ' + (m in r.verdicts ? (r.verdicts[m] ? 'b' : '') : 'na'), title: label(m) + ': ' + (m in r.verdicts ? (r.verdicts[m] ? 'blocked' : 'approved') : 'no run') })));

  function highlights() {
    // frontier models block, but several others approve the same PR
    const front = ['claude-opus-4-7', 'claude-sonnet-4-6'];
    return index.filter((r) => front.every((m) => r.verdicts[m] === true) &&
      Object.values(r.verdicts).filter((v) => v === false).length >= 3)
      .sort((a, b) => blockedCount(a) - blockedCount(b)).slice(0, 6);
  }

  function prCard(r) {
    return h('a', { class: 'card', href: '#/pr/' + r.slug },
      h('div', { class: 'name' }, h('span', {}, r.repo.split('/')[1]), dots(r)),
      h('div', {}, h('span', { class: 'tag' }, cweNum(r.cwe)), ' ', h('span', { class: 'tag' }, nice(r.framing))),
      h('div', { class: 'snip' }, r.title));
  }

  function renderIndex() {
    const rows = () => {
      let r = index.filter((x) =>
        (!filters.cwe || x.cwe === filters.cwe) && (!filters.framing || x.framing === filters.framing) &&
        (!filters.q || (x.title + ' ' + x.repo).toLowerCase().includes(filters.q.toLowerCase())) &&
        (!filters.model || !filters.outcome || (filters.model in x.verdicts && x.verdicts[filters.model] === (filters.outcome === 'blocked'))));
      const key = { cwe: (x) => x.cwe, repo: (x) => x.repo, framing: (x) => x.framing, blocked: blockedCount }[sortKey];
      return r.sort((a, b) => (key(a) > key(b) ? 1 : key(a) < key(b) ? -1 : 0) * sortDir);
    };
    const tbody = h('tbody');
    const count = h('span', { class: 'muted' });
    const draw = () => {
      const r = rows();
      count.textContent = `${r.length} of ${index.length} PRs`;
      tbody.replaceChildren(...r.map((x) => h('tr', { class: 'row', onclick: () => (location.hash = '#/pr/' + x.slug) },
        h('td', {}, h('span', { class: 'tag' }, cweNum(x.cwe))), h('td', {}, x.repo),
        h('td', {}, nice(x.framing)), h('td', {}, x.title), h('td', {}, dots(x)),
        h('td', {}, `${blockedCount(x)}/${Object.keys(x.verdicts).length}`))));
    };
    const sel = (key, opts, ph) => {
      const s = h('select', { onchange: (e) => { filters[key] = e.target.value; draw(); } },
        h('option', { value: '' }, ph), opts.map(([v, t]) => h('option', { value: v, selected: filters[key] === v }, t)));
      return s;
    };
    const th = (k, t) => h('th', { onclick: () => { sortDir = sortKey === k ? -sortDir : 1; sortKey = k; draw(); } }, t);
    const stats = Object.keys(manifest.models).map((m) => {
      const v = index.filter((x) => m in x.verdicts);
      const b = v.filter((x) => x.verdicts[m]).length;
      return h('div', { class: 'stat' }, h('b', {}, v.length ? Math.round(100 * b / v.length) + '%' : '–'), label(m));
    });
    const hl = highlights();
    show(
      h('h1', {}, 'Review traces'),
      h('p', { class: 'lead' }, 'Browse how LLM review agents handled malicious pull requests in Sevra-Bench: the PR as the reviewer saw it, each model’s verdict side by side, and the full trajectory behind every verdict. This is a curated subset of the retained challenge split, so rates below describe the subset, not the paper’s results.'),
      h('h2', {}, 'Block rate on this subset'), h('div', { class: 'stats' }, stats),
      hl.length ? [h('h2', {}, 'Highlights: frontier Claude models block it, others approve'), h('div', { class: 'grid' }, hl.map(prCard))] : null,
      h('h2', {}, 'All PRs'),
      h('div', { class: 'filters' },
        sel('cwe', manifest.cwes.map((c) => [c, cweNum(c)]), 'All CWEs'),
        sel('framing', manifest.framings.map((f) => [f, nice(f)]), 'All framings'),
        sel('model', Object.keys(manifest.models).map((m) => [m, label(m)]), 'Any model'),
        sel('outcome', [['blocked', 'blocked'], ['approved', 'approved']], 'Any outcome'),
        h('input', { type: 'search', placeholder: 'Search title or repo', value: filters.q, oninput: (e) => { filters.q = e.target.value; draw(); } }),
        count),
      h('p', { class: 'muted' }, 'Squares follow the model order of the legend: ', Object.keys(manifest.models).map(label).join(', '), '. Green = blocked, red = approved, outline = no run. Model and outcome filters apply together.'),
      h('table', {}, h('thead', {}, h('tr', {}, th('cwe', 'CWE'), th('repo', 'Repo'), th('framing', 'Framing'), h('th', {}, 'PR title'), h('th', {}, 'Verdicts'), th('blocked', 'Blocked'))), tbody));
    draw();
  }

  function diffEl(text) {
    const pre = h('pre', { class: 'diff' });
    for (const line of text.split('\n')) {
      const c = line.startsWith('+') && !line.startsWith('+++') ? 'add' : line.startsWith('-') && !line.startsWith('---') ? 'del' : line.startsWith('@@') ? 'hunk' : '';
      pre.append(h('span', { class: c }, line + '\n'));
    }
    return pre;
  }

  const verdictPill = (t) => h('span', { class: 'pill ' + (t.blocked ? 'b' : 'a') }, t.blocked ? 'blocked' : 'approved');

  function modelTabs(pr, current) {
    return h('div', { class: 'tabs' },
      h('a', { href: '#/pr/' + pr.slug, class: current ? '' : 'on' }, 'Overview'),
      Object.keys(pr.traces).map((m) => h('a', { href: `#/pr/${pr.slug}/${m}`, class: current === m ? 'on' : '' },
        label(m) + (pr.traces[m].blocked ? ' ✓' : ' ✗'))));
  }

  function prHeader(pr) {
    return [h('p', {}, h('a', { href: '#/' }, '← All PRs')),
      h('h1', {}, pr.title),
      h('div', { class: 'meta' }, h('span', { class: 'tag' }, cweNum(pr.cwe)), h('span', { class: 'tag' }, nice(pr.framing)), h('span', {}, pr.repo + ' #' + pr.pr_number))];
  }

  async function renderPR(slug, model) {
    const pr = await fetchJSON(`data/prs/${slug}.json`);
    if (model && pr.traces[model]) return renderTrace(pr, model);
    const rows = Object.entries(pr.traces).map(([m, t]) => {
      const last = [...t.steps].reverse().find((s) => s.role === 'assistant' && s.text);
      return h('a', { class: 'card', href: `#/pr/${slug}/${m}` },
        h('div', { class: 'name' }, h('span', {}, label(m)), verdictPill(t)),
        h('div', { class: 'snip' }, last ? last.text : '(no final message)'),
        h('div', { class: 'meta' }, h('span', {}, t.steps.filter((s) => s.role === 'assistant').length + ' turns'), t.tokens ? h('span', {}, t.tokens.toLocaleString() + ' tokens') : null));
    });
    show(prHeader(pr), modelTabs(pr, null),
      h('h2', {}, 'Verdicts'), h('div', { class: 'grid' }, rows),
      h('h2', {}, 'PR description (what the reviewer was told)'), h('div', { class: 'prbody' }, pr.body || '(empty)'),
      h('h2', {}, 'Diff'), pr.diff ? diffEl(pr.diff) : h('p', { class: 'muted' }, 'Diff not captured in the logs.'));
  }

  function renderTrace(pr, model) {
    const t = pr.traces[model];
    const stepEls = t.steps.map((s) => {
      const el = h('div', { class: 'step ' + s.role }, h('div', { class: 'who' }, s.role === 'tool' ? 'tool result · ' + (s.fn || '') : label(model)));
      if (s.reasoning) el.append(h('details', {}, h('summary', {}, 'Reasoning'), h('pre', {}, s.reasoning)));
      if (s.text) el.append(s.role === 'tool' ? h('details', {}, h('summary', {}, `Output (${s.text.length} chars)`), h('pre', {}, s.text)) : h('div', { class: 'msg' }, s.text));
      if (s.error) el.append(h('pre', {}, 'error: ' + s.error));
      for (const c of s.calls || []) el.append(h('div', { class: 'call' }, `${c.fn}(${JSON.stringify(c.args)})`));
      return el;
    });
    show(prHeader(pr), modelTabs(pr, model),
      h('div', { class: 'meta' }, verdictPill(t),
        h('span', {}, 'detection: ' + (t.outcome || '?')), h('span', {}, 'judge label: ' + (t.security_reason || '?')),
        t.tokens ? h('span', {}, t.tokens.toLocaleString() + ' tokens') : null, t.seconds ? h('span', {}, Math.round(t.seconds) + ' s') : null),
      t.judge ? h('details', {}, h('summary', {}, 'Judge note'), h('pre', {}, t.judge)) : null,
      h('h2', {}, 'Trajectory'), stepEls);
  }

  async function route() {
    const parts = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean);
    window.scrollTo(0, 0);
    try {
      if (!manifest) [manifest, index] = await Promise.all([fetchJSON('data/manifest.json'), fetchJSON('data/index.json')]);
      if (parts[0] === 'pr' && parts[1]) await renderPR(decodeURIComponent(parts[1]), parts[2] && decodeURIComponent(parts[2]));
      else renderIndex();
    } catch (e) {
      app.replaceChildren(h('p', {}, 'Could not load trace data. If you opened this file directly, serve the docs folder instead (python3 -m http.server).'), h('pre', {}, String(e)));
    }
  }
  addEventListener('hashchange', route);
  route();
})();
