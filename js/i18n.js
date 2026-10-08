/* ============================================================================
 * i18n.js — Tiny translation layer (English / हिन्दी / తెలుగు).
 *
 * Adding a language:
 *   1. Copy the `en` block into a new key (e.g. `fr`).
 *   2. Translate as many strings as you can — any key that is missing
 *      automatically falls back to English, so a partial translation works.
 *   3. Add the language button in index.html (data-lang="fr").
 *
 * Usage in HTML:  data-i18n="key"          -> text content
 *                 data-i18n-ph="key"       -> placeholder attribute
 * Usage in JS:    SCAM.t('key')
 * ==========================================================================*/
(function (g) {
  'use strict';
  var SCAM = (g.SCAM = g.SCAM || {});

  var DICT = {
    en: {
      'a11y.skip': 'Skip to the main content',
      'brand.name': 'Scam Message Analyzer',
      'brand.tag': 'Check before you click',
      'nav.settings': 'Settings',
      'hero.title': 'Is this message a scam?',
      'hero.promise': 'Paste it below. In two seconds you will know the risk, the exact type of attack, and what to do next — in plain words.',
      'hero.privacy': 'Private by design: your message never leaves this device. Nothing is uploaded and nothing is stored on a server.',
      'analyzer.heading': 'Message analyzer',
      'tab.message': 'Text / WhatsApp / Telegram',
      'tab.email': 'Email',
      'form.phone': 'Sender number (optional)',
      'form.phonePh': '+91 98765 43210',
      'form.message': 'The suspicious message',
      'form.messagePh': 'Paste the SMS, WhatsApp or Telegram message here…',
      'form.sender': 'From (sender address)',
      'form.replyTo': 'Reply-To (optional)',
      'form.subject': 'Subject',
      'form.subjectPh': 'Your account will be suspended today',
      'form.body': 'Body',
      'form.bodyPh': 'Paste the email body here…',
      'form.headersToggle': 'Show: raw email headers (optional, for SPF / DKIM / DMARC)',
      'form.headers': 'Raw headers',
      'form.samples': 'Try a sample:',
      'sample.kyc': 'Fake bank KYC',
      'sample.otp': 'OTP theft',
      'sample.job': 'Fake job',
      'sample.upi': 'UPI refund',
      'sample.ceo': 'CEO fraud',
      'sample.netflix': 'Fake Netflix email',
      'sample.safe': 'A normal message',
      'form.batchHint': 'Tip: paste several messages separated by a line with “---” to compare them all at once.',
      'btn.analyze': 'Analyze message',
      'btn.clear': 'Clear',
      'btn.close': 'Close',
      'btn.cancel': 'Cancel',
      'btn.clearAll': 'Yes, clear everything',
      'results.heading': 'Analysis results',
      'results.batchHeading': 'Batch results — sorted by risk',
      'results.topReasons': 'Top reasons for this score',
      'results.attacks': 'Attack types found',
      'results.evidence': 'Evidence marked in the message',
      'results.evidenceHint': 'Hover or tap a highlighted part to see why it was flagged.',
      'results.whatThisMeans': 'What this means',
      'results.wants': 'What the scammer wants',
      'results.how': 'How this scam works',
      'results.redFlags': 'Red flags found',
      'results.linkInspection': 'Link inspection',
      'results.linkNone': 'No links were found in this message.',
      'results.linkSafe': 'These links look ordinary — but never log in through a link someone sent you.',
      'results.linkDest': 'Real destination',
      'results.doNow': 'What to do now',
      'results.notToDo': 'What NOT to do',
      'results.original': 'The message you checked',
      'results.emailChecks': 'Email checks',
      'results.allClear': 'No red flags matched for this message.',
      'results.actions': 'Report actions',
      'result.copy': 'Copy report',
      'result.pdf': 'Download PDF',
      'result.json': 'Download JSON',
      'result.share': 'Share a safe summary',
      'result.another': 'Analyze another',
      'result.ai': 'AI second opinion',
      'result.aiNote': 'Optional: add your own API key in Settings to send this text to an AI for a second opinion. It leaves your device only when you turn this on.',
      'result.aiRun': 'Ask AI for a second opinion',
      'result.aiPending': 'Asking the AI…',
      'result.aiError': 'The AI could not be reached. Your rule-based result above is unaffected.',
      'result.aiNone': 'No second opinion yet.',
      'result.showFull': 'Show full message',
      'result.highlights': 'why it was flagged',
      'history.heading': 'This session’s checks',
      'history.clear': 'Clear all data',
      'history.filterLevel': 'Filter by risk level',
      'history.filterAttack': 'Filter by attack type',
      'history.sort': 'Sort order',
      'history.allLevels': 'All risk levels',
      'history.allAttacks': 'All attack types',
      'history.sortRisk': 'Risk: highest first',
      'history.sortNewest': 'Newest first',
      'history.sortOldest': 'Oldest first',
      'history.sortLowest': 'Risk: lowest first',
      'history.empty': 'Nothing here yet. Analyze a message and it will be saved in this browser only.',
      'history.noMatch': 'No items match these filters.',
      'history.open': 'Open report',
      'history.msg': 'message',
      'history.email': 'email',
      'level.safe': 'Safe',
      'level.low': 'Low risk',
      'level.medium': 'Medium risk',
      'level.high': 'High risk',
      'level.critical': 'Critical',
      'stats.heading': 'Your session at a glance',
      'stats.byLevel': 'Risk levels',
      'stats.byAttack': 'Most common attack types',
      'stats.timeline': 'Timeline of checks',
      'stats.total': 'Messages checked',
      'stats.avg': 'Average risk',
      'stats.top': 'Most common attack',
      'stats.flagged': 'Flagged as medium or worse',
      'learn.heading': '10 scam tricks — and how to spot them',
      'learn.sub': 'Two minutes here will save you a lot of worry later.',
      'learn.example': 'Real-looking example',
      'settings.title': 'Settings',
      'settings.language': 'Language',
      'settings.languageNote': 'More languages can be added — untranslated strings fall back to English.',
      'settings.aiTitle': 'Optional AI second opinion',
      'settings.aiWarn': 'Off by default. If you turn this on, the message text will be sent to the AI provider you choose, using your own key. Without a key, everything stays on this device.',
      'settings.aiEnable': 'Enable AI second opinion',
      'settings.aiProvider': 'Provider',
      'settings.aiKey': 'Your API key (stored only in this browser)',
      'settings.aiKeyNote': 'Never share this key. It is saved in this browser’s local storage only and is sent only to the provider you selected.',
      'settings.dataTitle': 'Your data',
      'settings.dataNote': 'Analysis history is saved in this browser only (localStorage). Nothing is sent anywhere.',
      'confirm.title': 'Clear all data?',
      'confirm.body': 'This deletes the analysis history and settings stored in this browser. It cannot be undone.',
      'footer.disclaimerTitle': 'Disclaimer:',
      'footer.disclaimer': 'This tool gives guidance, not a guarantee. It cannot know everything about a message. When in doubt, contact the company or bank directly using the number on their official website or app.',
      'footer.privacy': 'How your data is handled',
      'footer.about': 'About this tool',
      'footer.install': 'Install as an app',
      'footer.fine': 'Runs 100% in your browser. No accounts, no tracking, no server storage.',
      'info.privacyTitle': 'Your privacy',
      'info.aboutTitle': 'About this tool',
      'analyzing.1': 'Reading your message…',
      'analyzing.2': 'Checking links and addresses…',
      'analyzing.3': 'Matching known scam patterns…',
      'analyzing.4': 'Writing your plain-English report…',
      'toast.copied': 'Report copied to your clipboard.',
      'toast.shared': 'Summary shared.',
      'toast.shareCopied': 'Summary copied — paste it wherever you need.',
      'toast.json': 'JSON report downloaded.',
      'toast.pdf': 'Choose “Save as PDF” in the print window.',
      'toast.dataCleared': 'All data cleared from this browser.',
      'toast.sample': 'Sample loaded — press Analyze.',
      'err.empty': 'Paste a message first — even a screenshot’s text helps.',
      'err.long': 'That message is too long. Please paste the suspicious part only.',
      'level.verdict.safe': 'Nothing suspicious stood out. Still, never share passwords or OTPs.',
      'level.verdict.low': 'A few odd details. Slow down and double-check the sender before you act.',
      'level.verdict.medium': 'This looks suspicious. Do not click or reply — verify with the company directly.',
      'level.verdict.high': 'This looks like a scam. Do not click, do not reply, and warn your family.',
      'level.verdict.critical': 'Do not click. This is very likely a scam.'
    },

    hi: {
      'a11y.skip': 'मुख्य सामग्री पर जाएँ',
      'brand.name': 'स्कैम मैसेज एनालाइज़र',
      'brand.tag': 'क्लिक करने से पहले जाँचें',
      'nav.settings': 'सेटिंग्स',
      'hero.title': 'क्या यह मैसेज धोखाधड़ी है?',
      'hero.promise': 'नीचे चिपकाएँ। दो सेकंड में जोखिम, हमले का सही प्रकार और आगे क्या करना है — साधारण भाषा में पता चल जाएगा।',
      'hero.privacy': 'आपकी गोपनीयता सुरक्षित है: आपका मैसेज इस डिवाइस से बाहर नहीं जाता। कुछ भी अपलोड या सर्वर पर संग्रहित नहीं होता।',
      'analyzer.heading': 'मैसेज एनालाइज़र',
      'tab.message': 'टेक्स्ट / WhatsApp / Telegram',
      'tab.email': 'ईमेल',
      'form.phone': 'भेजने वाले का नंबर (वैकल्पिक)',
      'form.message': 'संदिग्ध मैसेज',
      'form.messagePh': 'यहाँ SMS, WhatsApp या Telegram मैसेज चिपकाएँ…',
      'form.sender': 'प्रेषक पता (From)',
      'form.replyTo': 'Reply-To (वैकल्पिक)',
      'form.subject': 'विषय (Subject)',
      'form.body': 'मुख्य भाग (Body)',
      'form.headersToggle': 'दिखाएँ: ईमेल हेडर (SPF / DKIM / DMARC के लिए)',
      'form.samples': 'नमूना आज़माएँ:',
      'sample.kyc': 'नकली बैंक KYC',
      'sample.otp': 'OTP चोरी',
      'sample.job': 'नकली नौकरी',
      'sample.upi': 'UPI रिफंड',
      'sample.ceo': 'CEO धोखाधड़ी',
      'sample.netflix': 'नकली Netflix ईमेल',
      'sample.safe': 'सामान्य मैसेज',
      'form.batchHint': 'सुझाव: कई मैसेज एक साथ जाँचने के लिए बीच में “---” वाली लाइन रखें।',
      'btn.analyze': 'मैसेज जाँचें',
      'btn.clear': 'साफ़ करें',
      'btn.close': 'बंद करें',
      'btn.cancel': 'रद्द करें',
      'btn.clearAll': 'हाँ, सब कुछ हटाएँ',
      'results.heading': 'जाँच के नतीजे',
      'results.topReasons': 'स्कोर के मुख्य कारण',
      'results.attacks': 'मिले हमले के प्रकार',
      'results.evidence': 'मैसेज में चिन्हित सबूत',
      'results.evidenceHint': 'किसी हाइलाइट हिस्से पर टैप करें — कारण दिखेगा।',
      'results.whatThisMeans': 'इसका मतलब',
      'results.wants': 'स्कैमर क्या चाहता है',
      'results.how': 'यह स्कैम कैसे काम करता है',
      'results.redFlags': 'मिले खतरे के संकेत',
      'results.linkInspection': 'लिंक जाँच',
      'results.linkNone': 'इस मैसेज में कोई लिंक नहीं मिला।',
      'results.linkDest': 'असली मंज़िल',
      'results.doNow': 'अब क्या करें',
      'results.notToDo': 'क्या नहीं करना है',
      'results.original': 'आपने जो मैसेज जाँचा',
      'results.allClear': 'इस मैसेज में कोई खतरे का संकेत नहीं मिला।',
      'results.actions': 'रिपोर्ट के विकल्प',
      'result.copy': 'रिपोर्ट कॉपी करें',
      'result.pdf': 'PDF डाउनलोड करें',
      'result.json': 'JSON डाउनलोड करें',
      'result.share': 'सुरक्षित सारांश साझा करें',
      'result.another': 'दूसरा मैसेज जाँचें',
      'result.ai': 'AI से दूसरी राय',
      'result.aiRun': 'AI से दूसरी राय लें',
      'history.heading': 'इस सत्र की जाँच',
      'history.clear': 'सभी डेटा हटाएँ',
      'history.allLevels': 'सभी जोखिम स्तर',
      'history.allAttacks': 'सभी हमले के प्रकार',
      'history.sortRisk': 'जोखिम: सबसे ऊपर',
      'history.empty': 'अभी कुछ नहीं है। मैसेज जाँचें — रिकॉर्ड केवल इसी ब्राउज़र में रहेगा।',
      'level.safe': 'सुरक्षित',
      'level.low': 'कम जोखिम',
      'level.medium': 'मध्यम जोखिम',
      'level.high': 'उच्च जोखिम',
      'level.critical': 'गंभीर',
      'stats.heading': 'आपका सत्र',
      'stats.byLevel': 'जोखिम के स्तर',
      'stats.byAttack': 'सामान्य हमलों के प्रकार',
      'stats.timeline': 'जाँच की समय-रेखा',
      'learn.heading': '10 स्कैम तरीके — और उन्हें कैसे पहचानें',
      'learn.example': 'असली जैसा उदाहरण',
      'settings.title': 'सेटिंग्स',
      'settings.language': 'भाषा',
      'settings.aiTitle': 'वैकल्पिक AI राय',
      'settings.aiEnable': 'AI दूसरी राय चालू करें',
      'settings.dataTitle': 'आपका डेटा',
      'settings.dataNote': 'जाँच का इतिहास केवल इसी ब्राउज़र में संग्रहित है। कुछ भी कहीं नहीं भेजा जाता।',
      'confirm.title': 'सभी डेटा हटाएँ?',
      'confirm.body': 'इस ब्राउज़र में संग्रहित इतिहास और सेटिंग्स हट जाएँगी। इसे वापस नहीं लाया जा सकता।',
      'footer.disclaimerTitle': 'अस्वीकरण:',
      'footer.disclaimer': 'यह टूल मार्गदर्शन देता है, गारंटी नहीं। संदेह हो तो कंपनी या बैंक की आधिकारिक वेबसाइट पर दिए नंबर से सीधे संपर्क करें।',
      'footer.fine': '100% आपके ब्राउज़र में चलता है। कोई अकाउंट, ट्रैकिंग या सर्वर स्टोरेज नहीं।'
    },

    te: {
      'a11y.skip': 'ముఖ్య కంటెంట్‌కు వెళ్లండి',
      'brand.name': 'స్కామ్ మెసేజ్ అనలైజర్',
      'brand.tag': 'క్లిక్ చేసే ముందు తనిఖీ చేయండి',
      'nav.settings': 'సెట్టింగ్‌లు',
      'hero.title': 'ఈ మెసేజ్ మోసమా?',
      'hero.promise': 'దాన్ని ఇక్కడ అతికించండి. రెండు సెకన్లలో ప్రమాద స్థాయి, దాడి రకం, తర్వాత ఏం చేయాలో — సులభంగా తెలుస్తుంది.',
      'hero.privacy': 'మీ గోప్యత సురక్షితం: మీ మెసేజ్ ఈ పరికరం దాటి వెళ్ళదు. ఏమీ అప్‌లోడ్ కాదు, సర్వర్‌లో నిల్వ కాదు.',
      'tab.message': 'టెక్స్ట్ / WhatsApp / Telegram',
      'tab.email': 'ఈమెయిల్',
      'form.message': 'అనుమానాస్పద మెసేజ్',
      'form.messagePh': 'SMS, WhatsApp లేదా Telegram మెసేజ్ ఇక్కడ అతికించండి…',
      'form.samples': 'నమూనా చూడండి:',
      'btn.analyze': 'మెసేజ్ విశ్లేషించు',
      'btn.clear': 'తొలగించు',
      'btn.close': 'మూసివేయి',
      'btn.cancel': 'రద్దు',
      'results.heading': 'విశ్లేషణ ఫలితాలు',
      'results.doNow': 'ఇప్పుడు ఏం చేయాలి',
      'results.notToDo': 'ఏం చేయకూడదు',
      'results.linkInspection': 'లింక్ తనిఖీ',
      'history.heading': 'ఈ సెషన్ తనిఖీలు',
      'history.clear': 'అన్ని డేటా తొలగించు',
      'stats.heading': 'మీ సెషన్',
      'learn.heading': '10 స్కామ్ పద్ధతులు — వాటిని ఎలా గుర్తించాలి',
      'settings.title': 'సెట్టింగ్‌లు',
      'settings.language': 'భాష',
      'footer.disclaimerTitle': 'నిరాకరణ:',
      'footer.disclaimer': 'ఈ సాధనం మార్గదర్శనం ఇస్తుంది, హామీ కాదు. సందేహం ఉంటే కంపెనీ లేదా బ్యాంక్ అధికారిక వెబ్‌సైట్‌లోని నంబర్‌తో నేరుగా సంప్రదించండి.'
    }
  };

  var LANGS = [
    { code: 'en', label: 'EN' },
    { code: 'hi', label: 'हि' },
    { code: 'te', label: 'తె' }
  ];
  SCAM.LANGS = LANGS;

  var current = 'en';
  try {
    var saved = localStorage.getItem('sma_lang');
    if (saved && DICT[saved]) current = saved;
  } catch (e) {}

  SCAM.lang = function () { return current; };

  SCAM.t = function (key, vars) {
    var table = DICT[current] || DICT.en;
    var s = table[key];
    if (s === undefined) s = DICT.en[key];
    if (s === undefined) return key;
    if (vars) Object.keys(vars).forEach(function (k) { s = s.replace('{' + k + '}', vars[k]); });
    return s;
  };

  /* Apply translations to the whole document */
  SCAM.applyI18n = function (root) {
    var scope = root || document;
    scope.querySelectorAll('[data-i18n]').forEach(function (el) {
      el.textContent = SCAM.t(el.getAttribute('data-i18n'));
    });
    scope.querySelectorAll('[data-i18n-ph]').forEach(function (el) {
      el.setAttribute('placeholder', SCAM.t(el.getAttribute('data-i18n-ph')));
    });
    document.documentElement.lang = current;
    var lbl = document.getElementById('langLabel');
    if (lbl) {
      var m = LANGS.filter(function (l) { return l.code === current; })[0];
      lbl.textContent = m ? m.label : 'EN';
    }
  };

  SCAM.setLang = function (code) {
    if (!DICT[code]) code = 'en';
    current = code;
    try { localStorage.setItem('sma_lang', code); } catch (e) {}
    SCAM.applyI18n(document);
    if (SCAM.UI && SCAM.UI.rerender) SCAM.UI.rerender();
  };

  SCAM.hasLang = function (code) { return !!DICT[code]; };
  SCAM.DICT = DICT;
})(typeof globalThis !== 'undefined' ? globalThis : this);
