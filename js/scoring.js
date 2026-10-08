/* ============================================================================
 * scoring.js — Turns matched rules into an explainable 0-100 score.
 *
 * score = Σ matched signal weights
 *       + Σ email-check weights
 *       + link risk (capped)
 *       + attack-confidence bonus
 *       − "this looks genuinely legit" reducers
 *       clamped to 0..100
 *
 * Every point above is traceable to a rule in rules.js / links.js / email.js.
 * ==========================================================================*/
(function (g) {
  'use strict';
  var SCAM = (g.SCAM = g.SCAM || {});

  /* Things that, when present, suggest a genuine message (small deductions) */
  var REDUCERS = [
    { id: 'security_advice', points: -12, why: 'It tells you NOT to share the code — genuine senders always say this.',
      re: /\b(?:do\s?not|never|don'?t)\s+(?:share|reveal)\b[^\n]{0,40}\b(?:otp|password|code|pin|credentials)\b/i },
    { id: 'security_advice2', points: -12, why: 'It warns you never to share the code — genuine senders always say this.',
      re: /\b(?:otp|password|code|pin)\b[^\n]{0,80}\b(?:do\s?not|never|don'?t)\s+share\b/i },
    { id: 'ignore_if_not_you', points: -8, why: 'Genuine alerts tell you to ignore the message if you did not request it.',
      re: /\b(?:ignore|disregard)\s+(?:this|the\s+above)\b[^\n]{0,40}\b(?:if|when)\b[^\n]{0,30}\b(?:not\s+request|did\s+not|didn'?t)\b/i },
    { id: 'official_footer', points: -5, why: 'It has a normal company footer (unsubscribe, privacy policy).',
      re: /\b(?:unsubscribe|opt[-\s]?out|privacy\s+policy|terms\s+(?:of\s+)?(?:use|service))\b/i }
  ];

  /* --------------------------------------------------------------------- */
  /* Text helpers                                                           */
  /* --------------------------------------------------------------------- */
  function lower(s) { return String(s || '').toLowerCase(); }

  function findRanges(text, needle, note, out) {
    if (!needle) return;
    var hay = lower(text), hayN = lower(needle);
    var from = 0, idx;
    var count = 0;
    while ((idx = hay.indexOf(hayN, from)) !== -1 && count < 4) {
      out.push({ start: idx, end: idx + needle.length, note: note });
      from = idx + needle.length;
      count++;
    }
  }

  /* Merge overlapping highlight ranges, keeping every note */
  function mergeRanges(ranges) {
    ranges.sort(function (a, b) { return a.start - b.start || b.end - a.end; });
    var out = [];
    ranges.forEach(function (r) {
      var last = out[out.length - 1];
      if (last && r.start <= last.end) {
        last.end = Math.max(last.end, r.end);
        if (last.notes.indexOf(r.note) === -1) last.notes.push(r.note);
      } else {
        out.push({ start: r.start, end: r.end, notes: [r.note] });
      }
    });
    return out;
  }
  SCAM.mergeRanges = mergeRanges;

  /* Split a pasted block into several messages (batch mode) */
  SCAM.splitBatch = function (text) {
    if (!text) return [];
    var parts = text.split(/^[ \t]*(?:-{3,}|={3,}|#{3,}|~{3,})[ \t]*$/m);
    return parts.map(function (p) { return p.replace(/^\n+|\n+$/g, '').trim(); })
                .filter(function (p) { return p.length > 0; });
  };

  /* Odd phone-number patterns (message mode) */
  function checkPhone(phone, text) {
    var found = [];
    var combined = (phone || '') + ' ' + (text || '');
    var nums = combined.match(/\+?\d[\d\s()-]{7,16}\d/g) || [];
    nums.slice(0, 8).forEach(function (n) {
      var digits = n.replace(/\D/g, '');
      if (/^\+/.test(n.trim())) {
        var cc = n.trim().replace(/\D/g, '').slice(0, 2);
        if (cc !== '91' && cc !== '1') {
          found.push({ id: 'foreign_number', label: 'Foreign country number', weight: 7,
            explain: 'The number starts with +' + cc + ' — an international number is unusual for a local service and makes complaints harder.',
            evidence: [n.trim()] });
        }
      }
      if (digits.length >= 12 && !/^\+/.test(n.trim())) {
        found.push({ id: 'long_number', label: 'Very long number', weight: 5,
          explain: 'This is not a normal local number — it may be an account ID or a premium-rate line.',
          evidence: [n.trim()] });
      }
      if (/^(\d)\1{7,}$/.test(digits)) {
        found.push({ id: 'repeated_number', label: 'Repeated-digit number', weight: 6,
          explain: 'A number made of the same digit repeated is almost never real.',
          evidence: [n.trim()] });
      }
    });
    /* Country code + long number together = typical scammer format */
    if (phone && /^\+\d{1,3}[\s-]?\d{6,}/.test(phone) && !/^\+(91|1|44|61|65|971)\b/.test(phone.trim())) {
      found.push({ id: 'odd_sender_number', label: 'Odd sender number', weight: 6,
        explain: 'The sending number is in an unusual format — treat it as unverified.',
        evidence: [phone] });
    }
    return found;
  }

  /* Light "odd grammar / text message tells" heuristic */
  function checkGrammar(text) {
    var out = [];
    var m = text.match(/\b(?:plz|u r|ur\b|frnd|dis\b|dat\b|v\s+r|k\b|ty|tc|gv|bcz|kindly revert|do the needful)\b/gi);
    if (m) {
      out.push({ id: 'text_slang', label: 'Odd wording / shortcuts', weight: 4,
        explain: 'Official messages are written properly. Words like "' + m[0] + '" are common in low-effort scam texts.',
        evidence: m.slice(0, 3) });
    }
    return out;
  }

  /* --------------------------------------------------------------------- */
  /* Main analysis                                                          */
  /* --------------------------------------------------------------------- */
  SCAM.analyze = function (input) {
    var mode = input.mode || 'message';
    var body = input.body || '';
    var subject = input.subject || '';
    var sender = input.sender || '';
    var headers = input.headers || '';
    var phone = input.phone || '';

var text = mode === 'email'
    ? [subject, body].filter(Boolean).join('\n\n')
    : (input.text || body);
  if (!text.trim()) text = [sender, phone].filter(Boolean).join(' ');

  /* re-claim the exact string we scored against, so highlighted offsets match */
  var scoredText = text;

    var lowerText = lower(text);
    var ranges = [];
    var items = [];      /* explainable score items (signals + email checks + phone + grammar) */
    var attacks = [];
    var links = [];
    var score = 0;
    var attackPoints = 0;

    /* 1. Text signals */
    SCAM.SIGNALS.forEach(function (s) {
      var ev;
      try { ev = s.test(text, { lower: lowerText, mode: mode }); } catch (e) { ev = []; }
      ev = (ev || []).filter(Boolean);
      if (ev.length) {
        score += s.weight;
        items.push({ id: s.id, kind: 'signal', label: s.label, explain: s.explain, weight: s.weight, evidence: ev.slice(0, 4) });
        ev.slice(0, 4).forEach(function (e) { findRanges(text, e, s.label, ranges); });
      }
    });

    /* 2. Email-only checks */
    if (mode === 'email') {
      SCAM.checkEmail({ sender: sender, subject: subject, body: body, headers: headers }).forEach(function (c) {
        score += c.weight;
        items.push({ id: c.id, kind: 'email', label: c.label, explain: c.explain, weight: c.weight, evidence: c.evidence || [] });
        (c.evidence || []).forEach(function (e) { findRanges(text, e, c.label, ranges); findRanges(sender, e, c.label, ranges); });
      });
      /* header hints also highlight in the raw headers box (rendered separately) */
    }

    /* 3. Message-only checks */
    if (mode === 'message') {
      checkPhone(phone, text).concat(checkGrammar(text)).forEach(function (c) {
        score += c.weight;
        items.push({ id: c.id, kind: 'message', label: c.label, explain: c.explain, weight: c.weight, evidence: c.evidence || [] });
        (c.evidence || []).forEach(function (e) { findRanges(text, e, c.label, ranges); });
      });
    }

    /* 4. Link inspection */
    links = SCAM.inspectAllUrls(text);
    var linkPoints = 0;
    links.forEach(function (l) {
      linkPoints += l.score;
      if (l.score > 0) {
        findRanges(text, l.url, 'Suspicious link', ranges);
        l.flags.forEach(function (f) {
          items.push({ id: 'link:' + l.host, kind: 'link', label: 'Link problem: ' + l.host, explain: f, weight: 0, evidence: [l.url] });
        });
      }
    });
    linkPoints = Math.min(26, linkPoints);
    score += linkPoints;
    if (linkPoints > 0) {
      items.push({ id: 'link_total', kind: 'link', label: 'Link risk', weight: linkPoints,
        explain: links.filter(function (l) { return l.score > 0; }).length + ' link(s) look unsafe.',
        evidence: links.filter(function (l) { return l.score > 0; }).map(function (l) { return l.url; }) });
    }

    /* 5a. Reducers (genuine-looking traits) — computed first so they can tone
           down scary-but-legit OTP messages below. */
    var reductions = [], redIds = {};
    REDUCERS.forEach(function (r) {
      if (r.re.test(text)) {
        score += r.points;
        reductions.push(r);
        redIds[r.id] = true;
        items.push({ id: r.id, kind: 'reducer', label: 'Good sign', explain: r.why, weight: r.points, evidence: [] });
      }
    });

    /* 5. Attack type detection */
    var geniusY = !!redIds.security_advice || !!redIds.security_advice2;
    SCAM.ATTACKS.forEach(function (a) {
      var conf = 0, evidence = [];
      a.patterns.forEach(function (pair) {
        var re = pair[0], w = pair[1];
        var m;
        var r = new RegExp(re.source, (re.flags || '').indexOf('g') === -1 ? (re.flags || 'i') + 'g' : re.flags);
        var matched = false;
        while ((m = r.exec(text)) !== null) {
          matched = true;
          if (evidence.indexOf(m[0]) === -1 && evidence.length < 5) evidence.push(m[0]);
          if (m[0].length === 0) { r.lastIndex++; }
          if (evidence.length >= 5) break;
        }
        if (matched) conf += w;
      });
      if (evidence.length) evidence.slice(0, 5).forEach(function (e) { findRanges(text, e, a.name, ranges); });
      conf = Math.min(96, conf);

      /* If the message looks genuinely safe ("do not share this OTP"),
         tone down credential-stealing labels so a real OTP is not called a scam. */
      if (geniusY && (a.family === 'credential' || a.id === 'smishing')) {
        conf = Math.round(conf * 0.3);
      }
      if (conf >= 45) {
        attacks.push({
          id: a.id, name: a.name, family: a.family, how: a.how, wants: a.wants,
          confidence: conf, evidence: evidence
        });
        attackPoints += Math.ceil(conf / 2.2);
      }
    });
    attacks.sort(function (x, y) { return y.confidence - x.confidence; });
    attackPoints = Math.min(35, attackPoints);
    score += attackPoints;

    score = Math.max(0, Math.min(100, Math.round(score)));
    var level = SCAM.levelFor(score);

    /* 7. Top 3 plain-language reasons */
    var ranked = items.filter(function (i) { return i.weight > 0; })
      .sort(function (a, b) { return b.weight - a.weight; });
    var reasons = ranked.slice(0, 3).map(function (i) { return i.label + ' — ' + i.explain; });

    /* 8. Highlighted copy */
    var merged = mergeRanges(ranges);
    var highlighted = buildHighlighted(text, merged);

    /* 9. Friendly summary sentence */
    var summary = buildSummary(score, level, attacks, items, text);

    /* 10. Checklists */
    var advice = buildAdvice(score, level, attacks, items, reductions);
    var notToDo = buildNotToDo(level, attacks);

    return {
      id: 'r' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      at: Date.now(),
      mode: mode,
      input: { sender: sender, subject: subject, phone: phone, text: scoredText, replyTo: input.replyTo || '' },
      score: score,
      level: level,
      summary: summary,
      reasons: reasons,
      items: items,
      attacks: attacks,
      links: links,
      reductions: reductions,
      highlightedHtml: highlighted,
      ranges: merged,
      advice: advice,
      notToDo: notToDo
    };
  };

  function buildHighlighted(text, ranges) {
    var out = '', pos = 0;
    ranges.forEach(function (r) {
      out += esc(text.slice(pos, r.start));
      out += '<mark class="ev" tabindex="0" data-note="' + esc(r.notes.join(' | ')) + '">' + esc(text.slice(r.start, r.end)) + '</mark>';
      pos = r.end;
    });
    out += esc(text.slice(pos));
    return out;
  }

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  SCAM.esc = esc;

  function buildSummary(score, level, attacks, items, text) {
    var empathy = [
      'You did the right thing by checking before acting.',
      'Checking first is always the smart move.',
      'Better to check twice than to be sorry later.'
    ];
    var line;
    if (attacks.length && score >= 75) {
      line = 'This looks like a ' + shortName(attacks[0].name) + '. Here is why we say so.';
    } else if (score >= 75) {
      line = 'This message is built to trick you — several tricks are stacked together.';
    } else if (score >= 50) {
      line = 'This looks suspicious. Treat it as unsafe until you have verified it another way.';
    } else if (score >= 25) {
      line = 'There are a few odd details, but nothing definite. Take your time and verify the sender.';
    } else if (items.length === 0) {
      line = 'Nothing in this message set off our checks.';
    } else {
      line = 'This looks mostly fine, with one or two small things worth a second look.';
    }
    return line + ' ' + empathy[(text.length + score) % empathy.length];
  }

  function shortName(n) {
    return n.replace(/\s*\(.*\)/, '').replace(/\//g, ' or ').toLowerCase();
  }

  function buildAdvice(score, level, attacks, items, reductions) {
    var list = [];
    var ids = {};
    items.forEach(function (i) { ids[i.id] = i; });

    if (level.id === 'safe') {
      list.push('Nothing to worry about from this message.');
      list.push('Still never share passwords, OTPs or card numbers with anyone who asks.');
      return list;
    }

    list.push('Do not click the link, do not reply, and do not call any number given in this message.');

    if (ids.credential_request || ids.remote_access || ids.personal_info) {
      list.push('If you already shared a password, OTP, PIN or card number: change your password now and lock your card from your bank app.');
    }
    if (ids.upi_request || ids.qr_request || ids.money_request || ids.callback_number) {
      list.push('If you already paid or approved a request, call your bank right away and ask them to reverse it.');
    }
    list.push('Report the message:');
    list.push('India: report on cybercrime.gov.in or call the 1930 helpline, and inform your bank.');
    list.push('Everywhere: mark it as spam/phishing in the app (WhatsApp, Gmail, SMS) and block the sender.');
    list.push('Tell a family member — especially older relatives — about this message.');

    var fams = {};
    attacks.forEach(function (a) { fams[a.family] = true; });
    Object.keys(fams).forEach(function (f) {
      (SCAM.ATTACK_ADVICE[f] || []).forEach(function (a) { if (list.indexOf(a) === -1) list.push(a); });
    });

    if (level.id === 'critical') {
      list.splice(1, 0, 'Take a breath — you have not lost anything by checking. Act quickly but calmly.');
    }
    return list;
  }

  function buildNotToDo(level, attacks) {
    var base = [
      'Do not share OTP, PIN, CVV or passwords with anyone — not even someone who says they are from your bank.',
      'Do not install an app or share your screen because a message asked you to.',
      'Do not pay a "fee" to release a prize, refund, salary or parcel.',
      'Do not forward this message to others as if it were real.',
      'Do not confront the scammer or try to trick them back — just stop replying.'
    ];
    if (level.id === 'safe') return ['You do not need to do anything. Just keep your details private.'];
    return base;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
