/* ============================================================================
 * ai.js — OPTIONAL AI "second opinion".
 *
 * Privacy rules:
 *   - Disabled by default. Without it, NO text ever leaves the device.
 *   - The key lives only in this browser's localStorage and is sent only to
 *     the provider you picked. It is never hardcoded or committed anywhere.
 *   - Before the first call we ask for explicit confirmation, so the user
 *     always knows text is about to leave the device.
 * ==========================================================================*/
(function (g) {
  'use strict';
  var SCAM = (g.SCAM = g.SCAM || {});
  var KEY = 'sma_ai_settings_v1';

  function load() {
    try { return JSON.parse(localStorage.getItem(KEY)) || {}; } catch (e) { return {}; }
  }
  function save(cfg) {
    try { localStorage.setItem(KEY, JSON.stringify(cfg)); } catch (e) {}
  }

  var PROMPT = [
    'You are a calm, friendly fraud analyst helping a non-technical person.',
    'Analyze the message below for scams. Reply with ONLY a JSON object, no markdown, exactly this shape:',
    '{"score": 0-100, "verdict": "one short friendly sentence",',
    ' "attacks": [{"name": "attack type", "confidence": 0-100, "why": "one sentence"}],',
    ' "red_flags": [{"flag": "short label", "explanation": "one plain sentence"}],',
    ' "advice": ["short action", "short action"]}',
    'Consider: phishing, smishing, vishing, quishing, UPI/payment fraud, OTP theft, fake bank/KYC,',
    'lottery, job, investment, romance, sextortion, tech-support, delivery, government/police impersonation,',
    'utility disconnection, loan apps, invoice fraud, malware, brand impersonation.',
    'Use plain, kind language. Never invent links that are not in the message.'
  ].join('\n');

  function extractJson(text) {
    var cleaned = String(text || '').replace(/```json\s*|```/g, '').trim();
    var start = cleaned.indexOf('{');
    var end = cleaned.lastIndexOf('}');
    if (start === -1 || end === -1) throw new Error('No JSON in reply');
    return JSON.parse(cleaned.slice(start, end + 1));
  }

  SCAM.AI = {
    settings: load,
    save: save,

    enabled: function () { return !!load().enabled; },
    hasKey: function () { return !!load().key; },

    /* Returns a normalised second opinion */
    ask: function (messageText) {
      var cfg = load();
      if (!cfg.enabled || !cfg.key) {
        return Promise.reject(new Error('AI mode is switched off (Settings).'));
      }
      var userText = String(messageText || '').slice(0, 8000);
      var req;
      if (cfg.provider === 'anthropic') {
        req = fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': cfg.key,
            'anthropic-version': '2023-06-01',
            'anthropic-dangerous-direct-browser-access': 'true'
          },
          body: JSON.stringify({
            model: 'claude-sonnet-4-5', max_tokens: 1200,
            system: PROMPT, messages: [{ role: 'user', content: userText }]
          })
        }).then(function (r) { return r.json(); }).then(function (d) {
          if (d.error) throw new Error(d.error.message || 'API error');
          var block = (d.content || []).filter(function (b) { return b.type === 'text'; })[0];
          return extractJson(block && block.text);
        });
      } else {
        req = fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=' +
            encodeURIComponent(cfg.key), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ parts: [{ text: PROMPT + '\n\nMESSAGE:\n' + userText }] }],
            generationConfig: { responseMimeType: 'application/json', temperature: 0.1 }
          })
        }).then(function (r) { return r.json(); }).then(function (d) {
          if (d.error) throw new Error(d.error.message || 'API error');
          var part = d.candidates && d.candidates[0] && d.candidates[0].content && d.candidates[0].content.parts[0];
          return extractJson(part && part.text);
        });
      }
      return req.then(function (data) {
        return {
          score: Math.max(0, Math.min(100, Math.round(Number(data.score) || 0))),
          verdict: String(data.verdict || ''),
          attacks: (data.attacks || []).slice(0, 5).map(function (a) {
            return { name: String(a.name || ''), confidence: Math.min(100, Number(a.confidence) || 50), why: String(a.why || '') };
          }),
          redFlags: (data.red_flags || []).slice(0, 8).map(function (f) {
            return { flag: String(f.flag || ''), explanation: String(f.explanation || '') };
          }),
          advice: (data.advice || []).slice(0, 6).map(String)
        };
      });
    },

    /* One-line notice shown before any text is sent */
    notice: function () {
      var cfg = load();
      var who = cfg.provider === 'anthropic' ? 'Anthropic' : 'Google';
      return 'AI mode is ON: the message text will be sent to ' + who + ' using your own key.';
    }
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
