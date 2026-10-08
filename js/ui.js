/* ============================================================================
 * ui.js — Renders the results dashboard, history, statistics and Learn list.
 * ==========================================================================*/
(function (g) {
  'use strict';
  var SCAM = (g.SCAM = g.SCAM || {});
  var t = SCAM.t;

  /* ───────────────────────── helper builders ───────────────────────── */
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function fmtTime(ms) {
    try {
      var d = new Date(ms);
      return d.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
    } catch (e) { return new Date(ms).toISOString(); }
  }

  function btnCls(iconCls, label) {
    var b = el('button', 'btn small');
    var s = el('span', 'btn-icon', iconCls);
    b.appendChild(s);
    b.appendChild(document.createTextNode(label));
    return b;
  }

  /* ─────────────────────────── main render ─────────────────────────── */
  function renderResult(result, opts) {
    opts = opts || {};
    var box = document.getElementById('resultsBody');
    box.innerHTML = '';
    SCAM.UI.currentResult = result;
    SCAM.UI.currentOpts = opts;

    var page = el('div', 'report-page');
    page.dataset.rptId = result.id;

    /* --- A. Batch banner (when several messages were analyzed) --- */
    if (opts.batch && opts.batch.length > 1) {
      var batchBar = el('div', 'batch-bar');
      batchBar.appendChild(el('strong', null, t('results.batchHeading') + ' (' + opts.batch.length + ')'));
      var bwrap = el('div', 'batch-list');
      opts.batch.slice().sort(function (a, b) { return b.score - a.score; }).forEach(function (r) {
        var pill = el('button', 'pill level-' + r.level.id);
        pill.textContent = r.score + ' — ' + preview(r) + (r.attacks[0] ? ' · ' + r.attacks[0].name : '');
        pill.title = 'Open this report';
        pill.setAttribute('aria-label', 'Open report for ' + preview(r));
        pill.addEventListener('click', function () { goTo(r); });
        bwrap.appendChild(pill);
      });
      batchBar.appendChild(bwrap);
      page.appendChild(batchBar);
    }

    /* --- B. Verdict header --- */
    var head = el('div', 'verdict-head');
    head.style.borderColor = result.level.color;
    var badge = el('div', 'verdict-badge');
    badge.style.background = result.level.color;
    var bi = el('span', 'verdict-icon', result.level.icon);
    var bl = el('span', 'verdict-label', result.level.label);
    badge.appendChild(bi); badge.appendChild(bl);
    head.appendChild(badge);

    var meta = el('div', 'verdict-meta');
    meta.appendChild(el('span', 'mode-tag', result.mode === 'email' ? t('history.email') : t('history.msg')));
    meta.appendChild(el('span', 'time-tag', fmtTime(result.at)));
    head.appendChild(meta);
    page.appendChild(head);

    /* --- C. Score + verdict --- */
    var scoreRow = el('div', 'score-row');
    var svg = el('svg', 'gauge');
    svg.setAttribute('width', '200'); svg.setAttribute('height', '110');
    SCAM.Charts.gauge(svg, result.score, result.level.color);
    scoreRow.appendChild(svg);

    var verdict = el('div', 'verdict-text');
    var vt = el('p', 'verdict-line', t('level.verdict.' + result.level.id));
    vt.style.color = result.level.color;
    var sum = el('p', 'summary-line', result.summary);
    verdict.appendChild(vt); verdict.appendChild(sum);
    scoreRow.appendChild(verdict);
    page.appendChild(scoreRow);

    /* --- D. Top 3 reasons --- */
    var reasonsBox = el('div', 'block');
    reasonsBox.appendChild(sectionTitle('results.topReasons'));
    var rwrap = el('div', 'reason-grid');
    (result.reasons && result.reasons.length ? result.reasons : ['Nothing was flagged in this message.']).slice(0, 3).forEach(function (r) {
      var card = el('div', 'reason-card');
      var n = el('span', 'reason-num');
      var dot = document.createElement('span');
      dot.className = 'reason-dot';
      dot.style.background = result.level.color;
      n.appendChild(dot);
      card.appendChild(n);
      card.appendChild(el('p', 'reason-text', r));
      rwrap.appendChild(card);
    });
    reasonsBox.appendChild(rwrap);
    page.appendChild(reasonsBox);

    /* --- E. Attack cards --- */
    if (result.attacks.length) {
      var atkTitle = sectionTitle('results.attacks');
      atkTitle.appendChild(el('span', 'count-tag', String(result.attacks.length)));
      var atkBox = el('div', 'block');
      atkBox.appendChild(atkTitle);
      var grid = el('div', 'attack-grid');
      result.attacks.forEach(function (a) {
        var card = el('div', 'attack-card');
        var top = el('div', 'attack-top');
        top.appendChild(el('h4', 'attack-name', a.name));
        var conf = el('span', 'conf', a.confidence + '%');
        conf.style.color = a.confidence >= 80 ? '#8E1F1B' : a.confidence >= 60 ? '#A85D14' : '#B23B2E';
        top.appendChild(conf);
        card.appendChild(top);
        card.appendChild(el('p', 'attack-how', a.how));
        card.appendChild(el('p', 'attack-wants', '<strong>' + t('results.wants') + '</strong> ' + a.wants));
        var flags = el('div', 'attack-flags');
        flags.appendChild(el('span', 'flags-label-inline', t('results.redFlags')));
        var ul = el('ul', 'flag-list');
        (a.evidence || []).slice(0, 5).forEach(function (ev) {
          var li = el('li', 'ev-chip', short(ev, 60));
          ul.appendChild(li);
        });
        flags.appendChild(ul);
        card.appendChild(flags);
        grid.appendChild(card);
      });
      atkBox.appendChild(grid);
      page.appendChild(atkBox);
    } else if (result.ranges && result.ranges.length) {
      /* evidence but no named attack — still show the flagged items */
    }

    /* --- F. Highlighted original message --- */
    var msgBox = el('div', 'block');
    msgBox.appendChild(sectionTitle('results.original'));
    var note = el('p', 'fine', t('results.evidenceHint'));
    msgBox.appendChild(note);
    var pre = el('div', 'highlighted mono');
    if (result.highlightedHtml) {
      pre.innerHTML = result.highlightedHtml;
    } else {
      pre.textContent = result.input.text || '';
    }
    if (!result.highlightedHtml && result.reasons.length === 0) {
      msgBox.appendChild(el('p', 'allclear', t('results.allClear')));
    }
    msgBox.appendChild(pre);
    page.appendChild(msgBox);

    /* --- G. Link inspection --- */
    var linksBox = el('div', 'block');
    linksBox.appendChild(sectionTitle('results.linkInspection'));
    if (!result.links.length) {
      linksBox.appendChild(el('p', 'link-none', t('results.linkNone')));
    } else {
      var safeCount = result.links.filter(function (l) { return l.safe; }).length;
      if (safeCount === result.links.length) {
        linksBox.appendChild(el('p', 'link-safe', t('results.linkSafe')));
      }
      var lt = el('div', 'links-table');
      result.links.forEach(function (l) {
        var row = el('div', 'link-row');
        if (l.safe) row.classList.add('link-ok') ; else row.classList.add('link-bad');
        var dest = el('div', 'link-dest');
        dest.appendChild(el('span', 'link-host', l.host || '?'));
        var raw = el('span', 'link-raw cliplink', l.url);
        raw.title = 'Click to copy this address';
        raw.tabIndex = 0;
        raw.addEventListener('click', function () { copyText(l.url); });
        dest.appendChild(raw);
        row.appendChild(dest);
        if (l.flags.length) {
          var fl = el('ul', 'link-flags');
          l.flags.slice(0, 4).forEach(function (f) { fl.appendChild(el('li', null, f)); });
          row.appendChild(fl);
        } else {
          row.appendChild(el('p', 'link-noflag', t('results.linkSafe')));
        }
        lt.appendChild(row);
      });
      linksBox.appendChild(lt);
    }
    page.appendChild(linksBox);

    /* --- H. Email checks --- */
    if (result.mode === 'email') {
      var emailItems = result.items.filter(function (i) { return i.kind === 'email'; });
      if (emailItems.length) {
        var emBox = el('div', 'block');
        emBox.appendChild(sectionTitle('results.emailChecks'));
        emailItems.forEach(function (i) {
          var card = el('div', 'flag-card');
          card.style.borderLeftColor = result.level.color;
          card.appendChild(el('div', 'flag-title', i.label));
          card.appendChild(el('div', 'flag-expl', i.explain));
          emBox.appendChild(card);
        });
        page.appendChild(emBox);
      }
    }

    /* --- I. Do now / Not to do --- */
    var adv = el('div', 'advice-grid');
    var doBox = el('div', 'block do-box');
    doBox.appendChild(sectionTitle('results.doNow'));
    var ol = el('ol', 'checklist');
    (result.advice || []).forEach(function (a) { ol.appendChild(el('li', null, a)); });
    doBox.appendChild(ol);
    adv.appendChild(doBox);

    var notBox = el('div', 'block not-box');
    notBox.appendChild(sectionTitle('results.notToDo'));
    var ul2 = el('ul', 'checklist-x');
    (result.notToDo || []).forEach(function (a) { ul2.appendChild(el('li', null, a)); });
    notBox.appendChild(ul2);
    adv.appendChild(notBox);
    page.appendChild(adv);

    /* --- J. AI second opinion --- */
    if (SCAM.AI.enabled() && SCAM.AI.hasKey()) {
      var aiBox = el('div', 'block ai-box');
      var aiT = sectionTitle('result.ai');
      aiBox.appendChild(aiT);
      var row = el('div', 'ai-row');
      var btn = btnCls('🤖', t('result.aiRun'));
      btn.addEventListener('click', function () { askAI(result); });
      var status = el('span', 'ai-status');
      status.dataset.aiStatus = 'idle';
      row.appendChild(btn);
      row.appendChild(status);
      aiBox.appendChild(row);
      page.appendChild(aiBox);
    } else if (SCAM.AI.enabled() && !SCAM.AI.hasKey()) {
      /* key missing — prompt in settings, label handled elsewhere */
    }

    /* --- K. Actions --- */
    var act = el('div', 'actions report-actions');
    var copyB = btnCls('📋', t('result.copy'));
    copyB.addEventListener('click', function () { copyReport(result); });
    var pdfB = btnCls('🖨️', t('result.pdf'));
    pdfB.addEventListener('click', function () { downloadPdf(result); });
    var jsonB = btnCls('💾', t('result.json'));
    jsonB.addEventListener('click', function () { downloadJson(result); });
    var shareB = btnCls('🔗', t('result.share'));
    shareB.addEventListener('click', function () { shareResult(result); });
    var againB = btnCls('➕', t('result.another'));
    againB.addEventListener('click', function () { resetForm(); });
    act.appendChild(copyB); act.appendChild(pdfB); act.appendChild(jsonB);
    act.appendChild(shareB); act.appendChild(againB);
    page.appendChild(act);

    box.appendChild(page);
    document.getElementById('results').hidden = false;
    document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function preview(r) {
    var raw = (r.input.text && r.input.text.trim()) || r.input.subject || '';
    return (raw.length > 46 ? raw.slice(0, 46) + '…' : raw) || r.summary || '—';
  }

  function short(s, n) {
    return String(s).length > n ? String(s).slice(0, n) + '…' : String(s);
  }

  function sectionTitle(key) {
    var h = el('h3', 'section-title', t(key));
    return h;
  }

  /* goTo uses either a history entry or a fresh result object */
  function goTo(entry) {
    var full;
    if (entry.full) full = entry.full;
    else if (entry.id && entry.score !== undefined && entry.highlightedHtml) full = entry;
    else {
      full = SCAM.History.get(entry.id);
      if (!full) {
        try { full = SCAM.analyze({ mode: entry.mode, text: entry.text, sender: entry.sender, subject: entry.subject, phone: entry.phone }); }
        catch (e) { return toast(t('err.empty')); }
      }
    }
    renderResult(full);
  }

  /* ───────────────────────── action handlers ───────────────────────── */
  function copyText(text) {
    var done = function () { toast(t('toast.copied')); };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
    } else { fallbackCopy(text); done(); }
  }

  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
  }

  function reportText(result) {
    var L = [];
    L.push('=== SCAM MESSAGE ANALYZER REPORT ===');
    L.push('Risk: ' + result.score + '/100 — ' + result.level.label);
    L.push('Checked: ' + fmtTime(result.at));
    L.push('');
    L.push('Verdict: ' + t('level.verdict.' + result.level.id));
    L.push(result.summary);
    L.push('');
    L.push('Top reasons:');
    result.reasons.forEach(function (r) { L.push('  • ' + r); });
    if (result.attacks.length) {
      L.push('');
      L.push('Attack types:');
      result.attacks.forEach(function (a) { L.push('  • ' + a.name + ' (' + a.confidence + '%) — ' + a.how); });
    }
    if (result.links.length) {
      L.push('');
      L.push('Links:');
      result.links.forEach(function (l) { L.push('  • ' + l.url + ' -> ' + l.host + (l.safe ? ' (ok)' : ' (suspicious)')); });
    }
    L.push('');
    L.push('What to do now:');
    result.advice.forEach(function (a) { L.push('  ✓ ' + a); });
    L.push('');
    L.push('What NOT to do:');
    result.notToDo.forEach(function (a) { L.push('  ✗ ' + a); });
    L.push('');
    L.push('--- Original message ---');
    L.push(result.input.text || '');
    L.push('');
    L.push('This report is guidance, not a guarantee.');
    return L.join('\n');
  }

  function copyReport(result) { copyText(reportText(result)); }

  function downloadJson(result) {
    var data = {
      tool: 'Scam Message Analyzer',
      ts: result.at, score: result.score, level: result.level.label,
      verdict: t('level.verdict.' + result.level.id), summary: result.summary,
      reasons: result.reasons, attacks: result.attacks, links: result.links,
      advice: result.advice, notToDo: result.notToDo,
      original: result.input.text
    };
    var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'scam-report-' + result.id + '.json';
    document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 400);
    toast(t('toast.json'));
  }

  function downloadPdf(result) {
    document.body.dataset.printId = result.id;
    var html = reportText(result).replace(/\n/g, '\n');
    var printDoc = document.getElementById('printDoc');
    if (!printDoc) {
      printDoc = document.createElement('div');
      printDoc.id = 'printDoc';
      document.body.appendChild(printDoc);
    }
    printDoc.textContent = html;
    window.print();
    toast(t('toast.pdf'));
  }

  function shareResult(result) {
    var text = 'Scam Message Analyzer says: ' + result.score + '/100 — ' + result.level.label + '. ' +
      t('level.verdict.' + result.level.id) + (result.attacks[0] ? ' Type: ' + result.attacks[0].name + '.' : '') +
      ' Check any suspicious message at this link.';
    var subject = 'Check this message — it might be a scam';
    if (navigator.share && window.isSecureContext) {
      navigator.share({ title: subject, text: text }).catch(function () { copyText(text); toast(t('toast.shareCopied')); });
      toast(t('toast.shared'));
    } else { copyText(text); toast(t('toast.shareCopied')); }
  }

  /* ─────────────────────────── AI helper ──────────────────────────── */
  function askAI(result) {
    if (!SCAM.AI.enabled()) return;
    if (!window.confirm(SCAM.AI.notice() + '\n\n' + t('result.aiNote'))) return;
    var status = document.querySelector('[data-ai-status]');
    var btn = status && status.parentElement.querySelector('.btn');
    if (btn) btn.disabled = true;
    if (status) status.textContent = t('result.aiPending');
    SCAM.AI.ask(result.input.text).then(function (opinion) {
      var box = status ? status.closest('.ai-box') : null;
      var body = el('div', 'ai-result');
      body.appendChild(el('p', 'ai-verdict', (opinion.verdict || '')));
      opinion.attacks.forEach(function (a) {
        body.appendChild(el('p', 'ai-attack', '• ' + a.name + ' — ' + a.why));
      });
      if (opinion.redFlags.length) {
        var rl = el('ul', 'checklist');
        opinion.redFlags.forEach(function (f) { rl.appendChild(el('li', null, f.flag + ' — ' + f.explanation)); });
        body.appendChild(rl);
      }
      if (opinion.advice.length) {
        var al = el('ol', 'checklist');
        opinion.advice.forEach(function (a) { al.appendChild(el('li', null, a)); });
        body.appendChild(al);
      }
      if (box) {
        var old = box.querySelector('.ai-result');
        if (old) old.remove();
        box.appendChild(body);
      }
      if (status) status.textContent = '';
      if (btn) btn.disabled = false;
    }).catch(function (err) {
      if (status) status.textContent = t('result.aiError');
      if (btn) btn.disabled = false;
    });
  }

  /* ───────────────────────── history & stats ──────────────────────── */
  var previewHtmlEls = [];

  function renderHistory() {
    var list = document.getElementById('historyList');
    var empty = document.getElementById('historyEmpty');
    if (!list) return;
    var all = SCAM.History.all();
    var filterLevel = document.getElementById('filterLevel').value;
    var filterAttack = document.getElementById('filterAttack').value;
    var sort = document.getElementById('sortOrder').value;

    var rows = all.filter(function (r) {
      if (filterLevel !== 'all' && r.level.id !== filterLevel) return false;
      if (filterAttack !== 'all') {
        var ok = r.attacks.some(function (a) { return a.id === filterAttack; });
        if (!ok) return false;
      }
      return true;
    });

    if (sort === 'risk') rows.sort(function (a, b) { return b.score - a.score || a.at - b.at; });
    else if (sort === 'lowest') rows.sort(function (a, b) { return a.score - b.score || a.at - b.at; });
    else if (sort === 'newest') rows.sort(function (a, b) { return b.at - a.at; });
    else rows.sort(function (a, b) { return a.at - b.at; });

    list.innerHTML = '';
    var hasBothFilters = filterLevel !== 'all' || filterAttack !== 'all';
    var sec = document.getElementById('historySection');
    if (sec) sec.hidden = all.length === 0;
    empty.hidden = all.length !== 0;
    var noMatch = el('p', 'empty');
    noMatch.textContent = t('history.noMatch');

    if (!rows.length) {
      if (all.length) list.appendChild(noMatch);
      return;
    }

    rows.forEach(function (r) {
      var li = el('li', 'history-item');
      var pill = el('span', 'score-pill level-' + r.level.id);
      pill.textContent = r.score;
      pill.title = r.level.label;
      li.appendChild(pill);
      var main = el('div', 'history-main');
      var txt = el('p', 'history-snippet', (r.subject || r.text || '—').replace(/\s+/g, ' ').slice(0, 90));
      var meta = el('div', 'history-meta');
      meta.appendChild(el('span', 'h-mode', r.mode === 'email' ? t('history.email') : t('history.msg')));
      meta.appendChild(el('span', 'h-time', fmtTime(r.at)));
      meta.appendChild(el('span', 'h-attacks', (r.attacks.slice(0, 2).map(function (a) { return a.name; }).join(', ') || '—')));
      main.appendChild(txt); main.appendChild(meta);
      li.appendChild(main);
      var open = el('button', 'btn tiny', t('history.open'));
      open.addEventListener('click', function () { goTo(r); });
      var del = el('button', 'btn tiny ghost-x', '✕');
      del.title = 'Remove from history';
      del.setAttribute('aria-label', 'Remove this check from history');
      del.addEventListener('click', function (e) {
        e.stopPropagation();
        SCAM.History.remove(r.id);
        renderHistory(); renderStats();
      });
      li.appendChild(open); li.appendChild(del);
      li.addEventListener('click', function (e) { if (e.target === li || e.target.closest('.history-main')) goTo(r); });
      li.addEventListener('keydown', function (e) { if (e.key === 'Enter') goTo(r); });
      li.tabIndex = 0;
      list.appendChild(li);
    });
  }

  function renderStats() {
    var s = SCAM.History.stats();
    var sec = document.getElementById('statsSection');
    if (!sec) return;
    sec.hidden = s.total === 0;
    if (s.total === 0) return;

    var grid = document.getElementById('statGrid');
    grid.innerHTML = '';
    var cells = [
      [t('stats.total'), String(s.total)],
      [t('stats.flagged'), String(s.flagged)],
      [t('stats.avg'), s.avg + '/100'],
      [t('stats.top'), s.topAttack || '—']
    ];
    cells.forEach(function (c) {
      var d = el('div', 'stat');
      d.appendChild(el('span', 'stat-num', c[1]));
      d.appendChild(el('span', 'stat-name', c[0]));
      grid.appendChild(d);
    });

    var lv = el('div', 'chart-box');
    SCAM.Charts.barChart(document.getElementById('chartLevels'),
      ['safe', 'low', 'medium', 'high', 'critical'].map(function (k) {
        return { label: t('level.' + k), value: s.byLevel[k] || 0, color: SCAM.Charts.LEVEL_COLORS[k] };
      }), { short: 6 });

    var attacks = Object.keys(s.byAttack)
      .map(function (k) { return { label: short(k, 18), value: s.byAttack[k] }; })
      .sort(function (a, b) { return b.value - a.value; }).slice(0, 7);
    SCAM.Charts.hbar(document.getElementById('chartAttacks'), attacks);

    SCAM.Charts.timeline(document.getElementById('chartTimeline'), s.items);
  }

  function renderLearn() {
    var list = document.getElementById('learnList');
    if (!list) return;
    list.innerHTML = '';
    SCAM.LEARN.forEach(function (item, i) {
      var det = el('details', 'learn-item');
      var sum = el('summary');
      var num = el('span', 'learn-num');
      num.textContent = String(i + 1).padStart(2, '0');
      sum.appendChild(num);
      sum.appendChild(document.createTextNode(' ' + item.title));
      det.appendChild(sum);
      det.appendChild(el('p', 'learn-body', item.body));
      var ex = el('p', 'learn-example');
      var exLbl = el('span', 'learn-example-label', t('learn.example') + ': ');
      ex.appendChild(exLbl);
      ex.appendChild(document.createTextNode(item.example));
      det.appendChild(ex);
      list.appendChild(det);
    });
  }

  function rerender() {
    if (SCAM.UI.currentResult) {
      renderResult(SCAM.UI.currentResult, SCAM.UI.currentOpts);
    }
    renderHistory();
    renderStats();
    renderLearn();
  }

  /* Need 'level' labels for filter options etc. */
  SCAM.UI = {
    renderResult: renderResult,
    renderHistory: renderHistory,
    renderStats: renderStats,
    renderLearn: renderLearn,
    rerender: rerender,
    formatTime: fmtTime,
    copyText: copyText,
    reportText: reportText,
    goTo: goTo
  };

  var toastTimer;
  function toast(msg) {
    var elNode = document.getElementById('toast');
    elNode.textContent = msg;
    elNode.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { elNode.hidden = true; }, 3200);
  }
  SCAM.UI.toast = toast;
})(typeof globalThis !== 'undefined' ? globalThis : this);