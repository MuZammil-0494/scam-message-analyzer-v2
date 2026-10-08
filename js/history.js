/* ============================================================================
 * history.js — Session history, kept ONLY in this browser (localStorage).
 *
 * Nothing here is ever sent to a server. "Clear all data" wipes it.
 * ==========================================================================*/
(function (g) {
  'use strict';
  var SCAM = (g.SCAM = g.SCAM || {});
  var KEY = 'sma_history_v2';
  var MAX = 60;

  function read() {
    try {
      var raw = localStorage.getItem(KEY);
      var arr = raw ? JSON.parse(raw) : [];
      return Array.isArray(arr) ? arr : [];
    } catch (e) { return []; }
  }

  function write(arr) {
    try { localStorage.setItem(KEY, JSON.stringify(arr.slice(0, MAX))); }
    catch (e) { /* storage full — drop the oldest */
      try { localStorage.setItem(KEY, JSON.stringify(arr.slice(0, 20))); } catch (e2) {}
    }
  }

  /* Trim a result so it fits comfortably in storage */
  function slim(r) {
    return {
      id: r.id, at: r.at, mode: r.mode, score: r.score,
      level: { id: r.level.id, label: r.level.label, icon: r.level.icon, color: r.level.color },
      summary: r.summary,
      text: (r.input.text || '').slice(0, 1500),
      subject: (r.input.subject || '').slice(0, 200),
      sender: (r.input.sender || '').slice(0, 200),
      phone: (r.input.phone || '').slice(0, 60),
      attacks: r.attacks.map(function (a) { return { id: a.id, name: a.name, confidence: a.confidence, family: a.family }; }),
      reasons: r.reasons,
      full: r
    };
  }

  SCAM.History = {
    all: function () { return read(); },

    add: function (result) {
      var arr = read();
      arr.unshift(slim(result));
      write(arr);
      return arr;
    },

    /* Full stored report (used by "Open report") */
    get: function (id) {
      var hit = read().filter(function (x) { return x.id === id; })[0];
      return hit ? hit.full : null;
    },

    remove: function (id) {
      write(read().filter(function (x) { return x.id !== id; }));
    },

    clear: function () {
      try { localStorage.removeItem(KEY); } catch (e) {}
    },

    stats: function () {
      var arr = read();
      var byLevel = { safe: 0, low: 0, medium: 0, high: 0, critical: 0 };
      var byAttack = {};
      var sum = 0;
      arr.forEach(function (r) {
        byLevel[r.level.id] = (byLevel[r.level.id] || 0) + 1;
        sum += r.score;
        r.attacks.forEach(function (a) {
          byAttack[a.name] = (byAttack[a.name] || 0) + 1;
        });
      });
      var top = Object.keys(byAttack).sort(function (a, b) { return byAttack[b] - byAttack[a]; });
      return {
        total: arr.length,
        avg: arr.length ? Math.round(sum / arr.length) : 0,
        byLevel: byLevel,
        byAttack: byAttack,
        topAttack: top[0] || null,
        flagged: arr.filter(function (r) { return r.score >= 50; }).length,
        items: arr.slice(0, 40).map(function (r) { return { at: r.at, score: r.score, level: r.level.id }; })
      };
    }
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
