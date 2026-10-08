/* ============================================================================
 * app.js — Wires everything together: tabs, analyze flow, settings, theme,
 * language, install prompt and the service worker.
 * ==========================================================================*/
(function () {
  'use strict';
  var SCAM = (window.SCAM = window.SCAM || {});
  var t = SCAM.t;

  /* ────────────────────────── element refs ────────────────────────── */
  var $ = function (id) { return document.getElementById(id); };
  var tabMessage = $('tabMessage'), tabEmail = $('tabEmail');
  var panelMessage = $('panelMessage'), panelEmail = $('panelEmail');
  var msgText = $('msgText'), msgPhone = $('msgPhone');
  var emSender = $('emSender'), emReplyTo = $('emReplyTo'), emSubject = $('emSubject'), emBody = $('emBody'), emHeaders = $('emHeaders');
  var analyzeBtn = $('analyzeBtn'), clearBtn = $('clearBtn');
  var analyzeState = $('analyzeState'), analyzeStep = $('analyzeStep');
  var errorMsg = $('errorMsg');

  var currentMode = 'message';

  /* ────────────────────────── tab switching ───────────────────────── */
  function setMode(mode) {
    currentMode = mode;
    var msg = mode === 'message';
    tabMessage.setAttribute('aria-selected', msg ? 'true' : 'false');
    tabEmail.setAttribute('aria-selected', msg ? 'false' : 'true');
    tabMessage.tabIndex = msg ? 0 : -1;
    tabEmail.tabIndex = msg ? -1 : 0;
    panelMessage.hidden = !msg;
    panelEmail.hidden = msg;
  }
  tabMessage.addEventListener('click', function () { setMode('message'); updateAnalyzeState(); });
  tabEmail.addEventListener('click', function () { setMode('email'); updateAnalyzeState(); });

  [tabMessage, tabEmail].forEach(function (tab) {
    tab.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
        e.preventDefault();
        var target = tab === tabMessage ? tabEmail : tabMessage;
        target.focus();
        target.click();
      }
    });
  });

  /* ──────────────────────── analyze enable state ─────────────────── */
  [msgText, emBody, emSubject, emSender, msgPhone].forEach(function (el) {
    ['input', 'paste', 'change'].forEach(function (evt) {
      el.addEventListener(evt, function () { setTimeout(updateAnalyzeState, 0); });
    });
  });

  function hasInput() {
    if (currentMode === 'email') {
      return (emBody.value.trim() || emSubject.value.trim() || emSender.value.trim());
    }
    return msgText.value.trim() || msgPhone.value.trim();
  }

  function updateAnalyzeState() {
    analyzeBtn.disabled = !hasInput();
  }

  /* ──────────────────────────── samples ──────────────────────────── */
  var SAMPLES = {
    kyc: { mode: 'message', text: 'Dear Customer, your ICICI a/c will be BLOCKED today. Update your KYC immediately by clicking http://icici-kyc-verify.in within 2 hours to avoid suspension. -Bank Team' },
    otp: { mode: 'message', text: 'Your Paytm login code is 449128. Share this OTP with our agent to complete the refund verification. Call now 011-4826-9900.' },
    job: { mode: 'message', text: 'Congratulations! You are hired for the Work From Home job. Pay Rs.250 registration fee to start earning Rs.3500 daily. WhatsApp 91 987xx for the task list.' },
    upi: { mode: 'message', text: 'You have received a payment request of Rs. 9,999. Your refund of Rs. 4,999 is pending. Scan this QR to claim it now. Reply YES to authorize.' },
    ceo: { mode: 'message', text: 'Hi, this is the CEO. I am in a meeting with the auditors. Kindly transfer Rs. 85,000 to this new account urgently and keep it between us. Do not call payroll.' },
    safe: { mode: 'message', text: 'Hi Mom, I will be home at 6 for dinner. Please pick up some bread on the way. Love you!' },
    netflix: { mode: 'email' }
  };
  var EMAIL_SAMPLE = {
    mode: 'email',
    sender: 'Netflix Support <support@netflix-login.verify-account.net>',
    replyTo: 'noreply@secure-mail.ru',
    subject: 'Your Netflix account will be suspended today',
    body: 'Dear user, your Netflix subscription could not be charged. Confirm your payment details now to avoid suspension: http://netflix-account-verify.xyz/login Click here to update. If you do not act within 24 hours your account will be closed.'
  };

  document.querySelectorAll('.chip[data-sample]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var s = SAMPLES[btn.dataset.sample];
      if (!s) return;
      setMode(s.mode);
      msgText.value = s.text || '';
      msgPhone.value = '';
      emSender.value = ''; emReplyTo.value = ''; emSubject.value = ''; emBody.value = ''; emHeaders.value = '';
      if (s.mode === 'email') {
        fillEmail(EMAIL_SAMPLE);
        setMode('email');
      }
      updateAnalyzeState();
      SCAM.UI.toast(t('toast.sample'));
    });
  });

  function fillEmail(s) {
    emSender.value = s.sender || '';
    emReplyTo.value = s.replyTo || '';
    emSubject.value = s.subject || '';
    emBody.value = s.body || '';
    emHeaders.value = s.headers || '';
  }

  /* ─────────────────────────── analyze flow ──────────────────────── */
  var STEP_MSGS = ['analyzing.1', 'analyzing.2', 'analyzing.3', 'analyzing.4'];
  var stepTimer;

  function showAnalyzing() {
    analyzeState.hidden = false;
    errorMsg.hidden = true;
    analyzeBtn.disabled = true;
    var i = 0;
    analyzeStep.textContent = t(STEP_MSGS[0]);
    stepTimer = setInterval(function () {
      i = (i + 1) % STEP_MSGS.length;
      analyzeStep.textContent = t(STEP_MSGS[i]);
    }, 700);
  }
  function hideAnalyzing() {
    clearInterval(stepTimer);
    analyzeState.hidden = true;
    updateAnalyzeState();
  }

  function gatherInput() {
    if (currentMode === 'email') {
      return { mode: 'email', sender: emSender.value.trim(), replyTo: emReplyTo.value.trim(),
        subject: emSubject.value.trim(), body: emBody.value, headers: emHeaders.value, text: emBody.value };
    }
    return { mode: 'message', phone: msgPhone.value.trim(), text: msgText.value };
  }

  analyzeBtn.addEventListener('click', function () {
    var input = gatherInput();
    var text = currentMode === 'email' ? (input.body || input.subject) : (input.text || input.phone);
    if (!text || !text.trim()) { errorMsg.textContent = t('err.empty'); errorMsg.hidden = false; return; }
    if (text.length > 12000) { errorMsg.textContent = t('err.long'); errorMsg.hidden = false; return; }

    showAnalyzing();
    setTimeout(function () {
      try {
        var parts = text.split(/^[ \t]*(?:-{3,}|={3,}|#{3,}|~{3,})[ \t]*$/m).map(function (p) { return p.trim(); })
          .filter(function (p) { return p.length; });
        var results;
        if (parts.length > 1 && currentMode !== 'email') {
          results = parts.map(function (p) {
            return SCAM.analyze({ mode: 'message', phone: input.phone, text: p });
          });
        } else {
          results = [SCAM.analyze(input)];
        }
        results.forEach(function (r) { SCAM.History.add(r); });
        var first = results[0];
        SCAM.UI.renderResult(first, { batch: results });
        refreshAll();
        hideAnalyzing();
      } catch (e) {
        window.onerror = null;
        errorMsg.textContent = 'Could not finish the analysis. (' + e.message + ')';
        errorMsg.hidden = false;
        hideAnalyzing();
      }
    }, 900);
  });

  clearBtn.addEventListener('click', resetForm);

  function resetForm() {
    msgText.value = ''; msgPhone.value = '';
    emSender.value = ''; emReplyTo.value = ''; emSubject.value = ''; emBody.value = ''; emHeaders.value = '';
    document.getElementById('results').hidden = true;
    $('resultsBody').innerHTML = '';
    SCAM.UI.currentResult = null;
    updateAnalyzeState();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
  window.resetForm = resetForm;

  function refreshAll() {
    refreshAttackFilter();
    SCAM.UI.renderHistory();
    SCAM.UI.renderStats();
  }

  /* attack-type filter options (filled from stored history) */
  function refreshAttackFilter() {
    var sel = $('filterAttack');
    var all = SCAM.History.all();
    var names = {};
    all.forEach(function (r) { r.attacks.forEach(function (a) { names[a.id + '|' + a.name] = a; }); });
    if (sel.options.length > 1 && Object.keys(names).length === sel.options.length - 1) return;
    sel.innerHTML = '';
    var o = document.createElement('option');
    o.value = 'all';
    o.textContent = t('history.allAttacks');
    sel.appendChild(o);
    Object.keys(names).sort().forEach(function (k) {
      var a = names[k];
      var op = document.createElement('option');
      op.value = a.id;
      op.textContent = a.name;
      sel.appendChild(op);
    });
  }

  ['filterLevel', 'filterAttack', 'sortOrder'].forEach(function (id) {
    $(id).addEventListener('change', function () { SCAM.UI.renderHistory(); });
  });

  /* ─────────────────────────── settings ─────────────────────────── */
  var settingsOverlay = $('settingsOverlay');
  $('settingsBtn').addEventListener('click', function () { openSettings(); });
  $('settingsClose').addEventListener('click', function () { closeSettings(); });
  settingsOverlay.addEventListener('click', function (e) { if (e.target === settingsOverlay) closeSettings(); });

  function openSettings() {
    var cfg = SCAM.AI.settings();
    $('aiEnabled').checked = !!cfg.enabled;
    $('aiProvider').value = cfg.provider || 'gemini';
    $('aiKey').value = cfg.key || '';
    settingsOverlay.hidden = false;
    document.querySelectorAll('#settingsOverlay .seg-btn').forEach(function (b) {
      b.classList.toggle('on', b.dataset.lang === SCAM.lang());
    });
  }
  function closeSettings() { settingsOverlay.hidden = true; }

  $('aiProvider').addEventListener('change', function () {
    var cfg = SCAM.AI.settings();
    cfg.provider = $('aiProvider').value;
    SCAM.AI.save(cfg);
  });
  $('aiKey').addEventListener('change', function () {
    var cfg = SCAM.AI.settings();
    cfg.key = $('aiKey').value.trim();
    SCAM.AI.save(cfg);
  });
  $('aiEnabled').addEventListener('change', function () {
    var cfg = SCAM.AI.settings();
    cfg.enabled = $('aiEnabled').checked;
    /* Confirm the user understands text will leave the device */
    if (cfg.enabled) {
      if (!window.confirm('AI second opinion ON.\n\n' + t('settings.aiWarn'))) {
        $('aiEnabled').checked = false;
        cfg.enabled = false;
      }
    }
    SCAM.AI.save(cfg);
    SCAM.UI.rerender();
    closeSettings();
  });

  document.querySelectorAll('#langSeg .seg-btn').forEach(function (b) {
    b.addEventListener('click', function () {
      SCAM.setLang(b.dataset.lang);
      openSettings();
      refreshAttackFilter();
    });
  });

  /* Language toggle in header */
  var langBtn = $('langBtn');
  if (langBtn) {
    langBtn.addEventListener('click', function () {
      var codes = ['en', 'hi', 'te'];
      var curr = SCAM.lang();
      var next = codes[(codes.indexOf(curr) + 1) % codes.length];
      SCAM.setLang(next);
      refreshAttackFilter();
      SCAM.UI.toast(t('settings.language') + ': ' + (next === 'en' ? 'English' : next === 'hi' ? 'हिन्दी' : 'తెలుగు'));
    });
  }

  /* ─────────────────────────── theme ────────────────────────────── */
  var themeBtn = $('themeBtn'), themeIcon = $('themeIcon');
  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('sma_theme', theme); } catch (e) {}
    themeIcon.textContent = theme === 'dark' ? '☀️' : '🌙';
    themeBtn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
  }
  themeBtn.addEventListener('click', function () {
    var next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    applyTheme(next);
  });
  applyTheme((function () {
    try {
      var p = localStorage.getItem('sma_theme');
      if (p) return p;
    } catch (e) {}
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  })());

  /* ─────────────────────────── clear data ───────────────────────── */
  var confirmOverlay = $('confirmOverlay');
  confirmOverlay.addEventListener('click', function (e) {
    if (e.target === confirmOverlay) {
      confirmOverlay.hidden = true;
    }
  });
  function confirmClear() {
    return new Promise(function (resolve) {
      confirmOverlay.hidden = false;
      $('confirmYes').onclick = function () { confirmOverlay.hidden = true; resolve(true); };
      $('confirmNo').onclick = function () { confirmOverlay.hidden = true; resolve(false); };
    });
  }
  function clearAllData() {
    confirmClear().then(function (ok) {
      if (!ok) return;
      SCAM.History.clear();
      SCAM.UI.rerender();
      closeSettings();
      SCAM.UI.toast(t('toast.dataCleared'));
    });
  }
  $('clearDataBtn').addEventListener('click', clearAllData);
  $('clearDataBtn2').addEventListener('click', clearAllData);

  /* ─────────────────────────── info modals ──────────────────────── */
  var infoOverlay = $('infoOverlay');
  function showInfo(title, html) {
    $('infoTitle').textContent = title;
    $('infoBody').innerHTML = html;
    infoOverlay.hidden = false;
  }
  $('infoClose').addEventListener('click', function () { infoOverlay.hidden = true; });
  infoOverlay.addEventListener('click', function (e) { if (e.target === infoOverlay) infoOverlay.hidden = true; });
  $('privacyBtn').addEventListener('click', function () {
    showInfo(t('info.privacyTitle'),
      '<p><strong>Nothing leaves your device by default.</strong></p>' +
      '<p>Your messages, sender addresses and analysis results are processed entirely in your browser. The rules engine runs locally. History is saved only in this browser\'s localStorage and deleted when you press "Clear all data".</p>' +
      '<p>The only exception is the OPTIONAL AI second opinion: if you switch it on in Settings and add your own key, the message text is sent to Google or Anthropic with your key. You are warned before that happens.</p>' );
  });
  $('aboutBtn').addEventListener('click', function () {
    showInfo(t('info.aboutTitle'),
      '<p>Scam Message Analyzer brings a transparent rule-based engine (see js/rules.js — editable) plus optional AI. No account, no tracking, no cost.</p>' +
      '<p>It covers fast-growing scams in India: UPI fraud, fake KYC and bank-alert links, digital-arrest calls, courier fees, electricity disconnection threats, loan-apps and more — alongside global ones like CEO fraud, romance scams and sextortion.</p>' +
      '<p><strong>Disclaimer:</strong> ' + t('footer.disclaimer') + '</p>' +
      '<p>Report scams in India: <a href="https://cybercrime.gov.in" rel="noopener" target="_blank">cybercrime.gov.in</a> or call 1930.</p>');
  });

  /* ─────────────────────────── install (PWA) ────────────────────── */
  var deferredPrompt;
  var installBtn = $('installBtn');
  window.addEventListener('beforeinstallprompt', function (e) {
    e.preventDefault();
    deferredPrompt = e;
    installBtn.hidden = false;
  });
  installBtn.addEventListener('click', function () {
    if (!deferredPrompt) return;
    deferredPrompt.prompt();
    deferredPrompt.userChoice.finally(function () { deferredPrompt = null; installBtn.hidden = true; });
  });
  window.addEventListener('appinstalled', function () { installBtn.hidden = true; });

  if ('serviceWorker' in navigator) {
    /* Reload once when an updated worker takes over, so fixes actually appear. */
    var hadController = !!navigator.serviceWorker.controller;
    navigator.serviceWorker.addEventListener('controllerchange', function () {
      if (!hadController) { hadController = true; return; }
      window.location.reload();
    });
    window.addEventListener('load', function () {
      navigator.serviceWorker.register('service-worker.js').catch(function () {});
    });
  }

  /* ───────────────────────────── init ───────────────────────────── */
  SCAM.applyI18n(document);
  renderFiltersInit();
  SCAM.UI.renderHistory();
  SCAM.UI.renderStats();
  SCAM.UI.renderLearn();

  function renderFiltersInit() {
    ['safe', 'low', 'medium', 'high', 'critical'].forEach(function () {});
    refreshAttackFilter();
  }

  /* escape handler for modal overlays */
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      ['settingsOverlay', 'infoOverlay', 'confirmOverlay'].forEach(function (id) { $(id).hidden = true; });
    }
  });

  /* Enter in text fields runs analysis (but not in textarea) */
  [emSender, emReplyTo, emSubject, msgPhone].forEach(function (el) {
    el.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && hasInput()) { e.preventDefault(); analyzeBtn.click(); }
    });
  });
})();