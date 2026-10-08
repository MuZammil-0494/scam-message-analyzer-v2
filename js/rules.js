/* ============================================================================
 * rules.js — The transparent, editable rule table.
 *
 * Everything the scoring engine knows lives here. No magic: each SIGNAL adds a
 * fixed number of points when it matches; each ATTACK is a bundle of weighted
 * patterns that produce a named attack type with a confidence %.
 *
 * How to edit:
 *   - Add a signal: push { id, label, explain, weight, test(text, ctx) }
 *   - Add an attack: add an entry to ATTACKS with patterns: [ [regex, weight] ]
 *   - Raise a weight => that signal counts for more of the 0-100 score.
 * ==========================================================================*/
(function (g) {
  'use strict';
  var SCAM = (g.SCAM = g.SCAM || {});

  /* Shared pattern fragments (reused by signals + attacks) */
  var P = {
    otp: /\b(otp|o\.t\.p|one[-\s]?time\s?(password|passcode|code)|verification\scode|security\scode|auth\s?code|login\scode|2fa\scode)\b/i,
    otpAsk: /\b(share|enter|send|reply\s with|tell\s me|provide|click\s to\s verify)[^\n]{0,40}\b(otp|verification\scode|one[-\s]?time\spassword|security\scode)\b/i,
    pin: /\b(atm\s?pin|upi\s?pin|cvv2?|expiry\sdate|card\s?number|internet\sbanking|net\s?banking\s?password|login\spassword)\b/i,
    accountThreat: /\b(account|a\/c|acct)\b[^\n]{0,40}\b(blocked|suspend[sd]?|locked|disabled|close[ds]?|deactivat\w+|restrict\w+)\b/i,
    kyc: /\b(kyc|know\syour\scustomer|re-?verification|update\syour\s(kyc|details|profile|account)|verify\syour\s(kyc|identity|account))\b/i,
    deadline: /\b(within|in|under|before|by)\s\d{1,4}\s?(hours?|hrs?|minutes?|mins?|days?|today|tonight|immediately|urgent\w*)\b|\b(right\snow|act\snow|hurry|last\s(chance|warning|day)|expires?\s(today|soon|in\s\d))\b/i,
    urgency: /\b(urgent|immediately|urgent\saction|asap|do\sit\snow|don'?t\sdelay|time\s-sensitive|final\snotice|last\snotice|expiry\s(today|soon))\b/i,
    threat: /\b(legal\s(action|notice)|police\s(case|arrest)?|arrest|fir\b|court\s(summons|notice)|blacklist\w*|penalt\w+|fine\b|prosecut\w+|case\s(being\s)?(filed|registered))\b/i,
    money: /\b(pay|send|transfer|deposit|fee(?:s)?|refundable\s?(fee|amount|charge)|processing\sfee|verification\sfee|activation\sfee|service\sfee|charge|amount|rs\.?\s?\d|usd|dollars?|inr)\b/i,
    prize: /\b(lottery|jackpot|prize|winner|won\b|giveaway|scratch\s?card|lucky\sdraw|reward|contest|windfall)\b/i,
    tooGood: /\b(free\s?(laptop|iphone|gift|trip|ticket|money|cash|coupon)|double\syour\smoney|work\sfrom\shome|part[-\s]?time\sjob|no\sexperience\sneeded|guaranteed\s(profit|returns?))\b/i,
    remoteAccess: /\b(anydesk|teamviewer|ultrasurf|quick\s?support|remote\s(desktop|support|access)|screen\s?share|install\s(this\s)?app|grant\spermission|allow\saccess)\b/i,
    credentials: /\b(password|passcode|username|user\s?name|account\s?(number|no\.?)|sort\scode|iban|ssn|social\ssecurity)\b/i,
    aadhaar: /\b(aadhaar|aadhar|uidai|pan\s?(card|number|no\.?|details)|\d{4}\s\d{4}\s\d{4})\b/i,
    upi: /\b(upi|gpay|google\s?pay|phonepe|paytm|bhim|collect\srequest|payment\srequest|refund\srequest|qr\s?code|scan\sthis\sqr|vpa)\b/i,
    authority: /\b(bank|sbi|hdfc|icici|axis|kotak|idfc|yes\s?bank|pnb|union\s?bank|baroda|federal\s?bank|police|itr|income\s?tax|gst|trai|rbi|sebi|irs|fbi|revenue|customs|post\s?office|passport\s?office|cyber\s?crime|google|gmail|netflix|paypal|amazon|microsoft|apple|instagram|whatsapp|flipkart)\b/i,
    delivery: /\b(delivery|parcel|courier|shipment|package|dhl|fedex|india\s?post|bluedart|amazon|flipkart|customs\s?(clearance|fee)|delivery\s?failed|undelivered)\b/i,
    utility: /\b(electricity|power\s?bill|gas\s?(cylinder|bill)|water\s?bill|lpg|bescom|mseb|tneb|disconnection|disconnect\w*|meter\s?reading|utility\s?bill)\b/i,
    genericGreeting: /\b(dear\s?(customer|user|member|subscriber|sir|madam|guest|account\s?holder|valued\s?customer)|to\s?whom\s?it\s?may\s?concern|dear\s?friend)\b/i,
    contactOffline: /\b(?:whatsapp|telegram|viber|signal)\b|\b(?:message|call|contact|ping|dm|pm|text)\s?(?:me|us)?\s?(?:on|at)?\s?[@+0-9]|\b(?:add|join)\s(?:me|us)\s?on\b/i,
    callback: /\b(call\s(this\s?)?number|dial\s\d|call\sus\s(at|on)|toll[-\s]?free|helpline\s?number|contact\snumber|call\s(now|immediately|within|us\snow))\b/i,
    qr: /\b(qr\s?code|qr\s?scan|scan\s+(the\s+)?(qr|code)|qrcode)\b/i,
    links: /\b(click\s(the\s+)?(link|below|here)|link\s(in|below)|verify\snow|update\snow|confirm\snow|claim\snow|login\snow|open\s?this\s?link)\b/i,
    job: /\b(job\s?(offer|vacancy|opening)|hiring|recruit\w+|work\s?from\s?home|wfh|data\s?entry|task\s?job|package\s?delivery|courier\s?job|salary\s?(of|:)\s?\d+|per\s?day\s?(pay|earning)|registration\s?fee)\b/i,
    invest: /\b(invest\w+|trading\s?(group|signal)|crypto|bitcoin|btc|eth|forex|share\s?market|stock\s?tips?|ipo\s?allotment|\bsip\b|mutual\sfund\s?guaranteed|fixed\s?return|monthly\s?income\s?scheme|pump\s?and\s?dump|binance|zerodha)\b/i,
    romance: /\b(dear\s?(love|honey|sweetheart)|i\slove\syou|soulmate|marry\sme|my\s(dear|love)\s\w+)\b/i,
    sextortion: /\b(explicit|morphed|obscene|video\s?(call|recording)|screen\s?record\w+|blackmail|embarrass\w+)\b/i,
    govThreat: /\b(digital\s?arrest|cyber\s?crime\s?branch|customs\s?(dept|department)|passport\s?(blocked|suspension)|tax\s?(refund|notice)|immigration|drug\s?(case|trafficking))\b/i,
    loan: /\b(loan\s?(approved|offer|app)|instant\sloan|pre[-\s]?approved\sloan|\bemi\b|bajaj|kreditbee|loan\s?pending|repay\w+\s?loan)\b/i,
    refund: /\b(refund|reimburse\w+|cashback|claim\syour\s(refund|amount)|unclaimed\s?(refund|amount)|tax\s?refund)\b/i,
    caps: /\b[A-Z]{7,}\b/,
    exclam: /!{2,}|\?{2,}/
  };
  SCAM.P = P;

  /* Known brands: look-alike domain detection + impersonation evidence */
  SCAM.BRANDS = [
    { name: 'PayPal', domains: ['paypal.com', 'paypal.me'], words: ['paypal'] },
    { name: 'Amazon', domains: ['amazon.com', 'amazon.in', 'amazonpay.in'], words: ['amazon'] },
    { name: 'Netflix', domains: ['netflix.com'], words: ['netflix'] },
    { name: 'Google', domains: ['google.com', 'accounts.google.com'], words: ['google', 'gmail'] },
    { name: 'Microsoft', domains: ['microsoft.com', 'live.com', 'outlook.com'], words: ['microsoft', 'outlook', 'onedrive'] },
    { name: 'Apple', domains: ['apple.com', 'icloud.com'], words: ['apple', 'icloud', 'itunes'] },
    { name: 'SBI', domains: ['sbi.co.in', 'onlinesbi.sbi'], words: ['sbi', 'state bank'] },
    { name: 'HDFC Bank', domains: ['hdfcbank.net', 'hdfcbank.in'], words: ['hdfc'] },
    { name: 'ICICI Bank', domains: ['icicibank.com', 'icicibank.in'], words: ['icici'] },
    { name: 'Axis Bank', domains: ['axisbank.co.in', 'axisbank.in'], words: ['axis bank'] },
    { name: 'Kotak', domains: ['kotak.com', 'kotakbank.in'], words: ['kotak'] },
    { name: 'WhatsApp', domains: ['whatsapp.com', 'whatsapp.net'], words: ['whatsapp'] },
    { name: 'Instagram', domains: ['instagram.com'], words: ['instagram'] },
    { name: 'Flipkart', domains: ['flipkart.com'], words: ['flipkart'] },
    { name: 'India Post', domains: ['indiapost.gov.in'], words: ['india post'] },
    { name: 'UIDAI / Aadhaar', domains: ['uidai.gov.in'], words: ['uidai'] },
    { name: 'Income Tax Dept', domains: ['incometax.gov.in'], words: ['income tax'] },
    { name: 'TRAI', domains: ['trai.gov.in'], words: ['trai'] },
    { name: 'DHL', domains: ['dhl.com'], words: ['dhl'] },
    { name: 'FedEx', domains: ['fedex.com'], words: ['fedex'] }
  ];

  SCAM.SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'ow.ly', 'cutt.ly', 'rb.gy',
    'shorturl.at', 's.id', 'bl.ink', 'lnkd.in', 'buff.ly', 't.ly', 'v.gd', 'cli.re', 'rebrand.ly',
    'soo.gd', 'gg.gg', 'zipy.io', 'trib.al', 'u.to', 'x.co', 'cfcut.com', 's2.ae'];

  SCAM.SUSPICIOUS_TLDS = ['zip', 'mov', 'xyz', 'top', 'club', 'work', 'click', 'link', 'gq', 'tk',
    'ml', 'cf', 'ga', 'buzz', 'loan', 'win', 'review', 'country', 'stream', 'download', 'racing',
    'accountant', 'science', 'date', 'faith', 'party', 'trade', 'webcam', 'cricket', 'men', 'rest',
    'host', 'cam', 'icu', 'cfd', 'sbs', 'cyou', 'pw', 'cc', 'su', 'vc', 'rest', 'today'];

  SCAM.KNOWN_SAFE_TLDS = ['com', 'in', 'org', 'gov', 'edu', 'net', 'co', 'io', 'dev', 'app', 'me'];

  function find(text, re) {
    var m = text.match(re);
    return m ? [m[0]] : [];
  }
  function findAll(text, re, limit) {
    var out = [], m;
    var r = new RegExp(re.source, 'gi');
    var max = limit || 4;
    while ((m = r.exec(text)) && out.length < max) {
      out.push(m[0]);
      if (m.index === r.lastIndex) r.lastIndex++;
    }
    return out;
  }
  SCAM._find = find;
  SCAM._findAll = findAll;

  /* SIGNALS — each adds `weight` points, once, when it matches. */
  SCAM.SIGNALS = [
    { id: 'urgency', label: 'Creates panic or urgency', weight: 12,
      explain: 'It pushes you to act before you can think. Deadlines stop you from checking first.',
      test: function (t) { return find(t, P.urgency).concat(find(t, P.deadline)); } },

    { id: 'threat', label: 'Threatens you with punishment', weight: 14,
      explain: 'Threats of arrest, legal action or a frozen account scare people into cooperating.',
      test: function (t) {
        return find(t, P.threat).concat(find(t, /\b(?:or\s(?:else\s)?(?:i\s)?(?:will\s|we\s)?(?:share|release|post|send|expose)\b|blackmail|i\s(?:have\s)?recorded\syour\s(video|screen|call))\b/i));
      } },

    { id: 'account_block', label: 'Claims your account will be blocked', weight: 16,
      explain: 'Fake "account blocked / KYC pending" alerts are one of the most common ways to steal logins in India.',
      test: function (t) { return find(t, P.accountThreat).concat(find(t, P.kyc)); } },

    { id: 'credential_request', label: 'Asks for a secret you should never share', weight: 22,
      explain: 'Banks, UPI apps and companies never ask for your OTP, PIN, CVV or password.',
      test: function (t) { return find(t, P.otpAsk).concat(find(t, P.otp)).concat(find(t, P.pin)); } },

    { id: 'personal_info', label: 'Asks for personal ID details', weight: 10,
      explain: 'Aadhaar, PAN and card numbers are used to steal your identity or drain your account.',
      test: function (t) { return find(t, P.aadhaar).concat(find(t, P.credentials)); } },

    { id: 'money_request', label: 'Asks for money, a fee or a payment', weight: 14,
      explain: 'Real prizes, jobs and refunds never ask you to pay money first.',
      test: function (t) { return find(t, P.money); } },

    { id: 'prize_bait', label: 'Promises a prize, lottery, refund or free gift', weight: 14,
      explain: 'You cannot win a draw you never entered, and real refunds never make you pay first. The "win" exists to take your fee.',
      test: function (t) { return find(t, P.prize).concat(find(t, /\b(?:unclaimed|pending)\s(?:refund|amount|balance|reward)\b/)).concat(find(t, /\b(?:processing|release|transfer)\s?fee\b[^\n]{0,40}\b(?:release|claim|receive|unlock)\b/)); } },

    { id: 'too_good', label: 'Too good to be true offer', weight: 10,
      explain: 'Easy money, free gadgets or guaranteed returns are classic bait.',
      test: function (t) { return find(t, P.tooGood).concat(find(t, /\bguaranteed\s\d{1,3}\s?%[^\n]{0,25}\b(?:return|profit|income|interest)\b/)); } },

    { id: 'release_fee', label: 'Asks you to pay a fee to release money', weight: 14,
      explain: 'A "small fee" to release a refund, prize or payment is the scam itself.',
      test: function (t) { return find(t, /\b(?:pay|deposit|transfer|send)\b[^\n]{0,50}\b(?:fee|charge|processing|token)\b[^\n]{0,50}\b(?:release|claim|receive|unlock|activate|continue)\b/); } },

    { id: 'discretion', label: 'Wants it kept secret ("between us")', weight: 10,
      explain: 'Genuine requests survive scrutiny. Asking you to hide it from colleagues is a control tactic.',
      test: function (t) { return find(t, /\b(?:between\s(?:us|you\sand\sme)|keep\s(?:this\s|it\s)?(?:quiet|private|secret)|do\s?not\s(?:discuss|tell\s+(?:anyone|anybody)|share|call)|confidential|only\syou(?!\btonight))\b/); } },

    { id: 'safe_account', label: 'Tells you to use a "safe / verified" account', weight: 14,
      explain: 'There is no such thing as a police "safe account". The money simply lands with the scammer.',
      test: function (t) {
        return find(t, /\b(?:safe|verified|government|frozen)\s?account\b/i)
          .concat(find(t, /\b(?:move|transfer|deposit|send|park)\b[^\n]{0,30}\b(?:safe|verified)\s?account\b/i));
      } },

    { id: 'emotional_plea', label: 'Pressure from a "romantic" stranger', weight: 12,
      explain: 'Fast "love" followed by a crisis asking for money is a scripted romance scam.',
      test: function (t) { return find(t, /\b(?:my\s(?:love|dear|darling|honey|sweetheart)|i\s(?:love|miss)\syou\b|fallen\sfor\syou|soulmate)\b/i).concat(find(t, /\b(?:please\s)?(?:help|send|transfer|deposit|pay)\s?(?:me|us)?\s?\d/i)); } },

    { id: 'remote_access', label: 'Wants remote access to your device', weight: 18,
      explain: 'Apps like AnyDesk or TeamViewer let a stranger control your phone, including your bank app.',
      test: function (t) { return find(t, P.remoteAccess); } },

    { id: 'qr_request', label: 'Pushes you to scan a QR code', weight: 12,
      explain: 'Scanning a QR code to "receive money" actually sends money OUT of your account.',
      test: function (t) { return find(t, P.qr); } },

    { id: 'upi_request', label: 'UPI / payment-request trick', weight: 14,
      explain: 'A "refund" or "collect request" in a UPI app is a payment you would be making to the scammer.',
      test: function (t) {
        var req = /\b(?:collect|payment|refund|money)\s?request\b|\bapprove\s(?:the\s)?(?:payment|request)\b|\breceived\s(?:a\s)?(?:refund|payment|money).?\s?request\b/i;
        var asksUpi = /\b(?:refund|receive|claim|transfer|pay|send)\b[^\n]{0,35}\b(?:upi|gpay|phonepe|paytm|vpa)\b/i;
        var scanPay = /\b(?:scan|scanning|show|share)\b[^\n]{0,30}\b(?:qr\s?code|upi\s?(?:id|address)|paytm|phonepe)\b/i;
        return find(t, req).concat(find(t, asksUpi)).concat(find(t, scanPay));
      } },

    { id: 'generic_greeting', label: 'Generic "Dear Customer" greeting', weight: 5,
      explain: 'Messages from your real bank are addressed to you by name, not to every customer.',
      test: function (t) { return find(t, P.genericGreeting); } },

    { id: 'off_platform', label: 'Moves you to WhatsApp / Telegram / a call', weight: 9,
      explain: 'Scammers move you away from the safe, traceable place where you first met them.',
      test: function (t) { return find(t, P.contactOffline); } },

    { id: 'callback_number', label: 'Tells you to call a number', weight: 8,
      explain: 'The number connects to a fake "support agent" trained to take your details (vishing).',
      test: function (t) { return find(t, P.callback); } },

    { id: 'click_pressure', label: 'Pushes you to click a link now', weight: 8,
      explain: '"Click below to verify" is how people reach phishing pages before checking the address.',
      test: function (t) { return find(t, P.links); } },

    { id: 'payment_verify', label: 'Asks you to "confirm payment" to avoid a penalty', weight: 16,
      explain: 'Real companies never make you confirm card details through a link to stop a service being closed.',
      test: function (t) { return find(t, /\b(?:confirm|verify|update)\b[^\n]{0,60}\b(?:payment|billing|card|subscription|account)\b[^\n]{0,60}\b(?:avoid|prevent|or\s(get|have)|else)\b/); } },

    { id: 'authority', label: 'Pretends to be a bank or authority', weight: 10,
      explain: 'Banks, police, TRAI and the Income Tax Department do not send payment links over SMS or WhatsApp.',
      test: function (t) { return find(t, P.authority); } },

    { id: 'shouting', label: 'ALL CAPS or excessive punctuation', weight: 4,
      explain: 'Shouting is used to create panic. Official notices are written calmly.',
      test: function (t) { return find(t, P.caps).concat(find(t, P.exclam)); } }
  ];

  /* ATTACK TYPES — named, explained, with weighted evidence patterns.
   * confidence = min(96, sum of the weights of the patterns that matched). */
  SCAM.ATTACKS = [
    { id: 'phishing', name: 'Phishing (credential harvesting)', family: 'credential',
      how: 'You are sent to a fake login page that looks like your bank, mail or wallet. Whatever you type goes straight to the scammer.',
      wants: 'Your username, password and OTP so they can log in as you.',
      patterns: [
        [/\b(verif(?:y|ication)|update|confirm|secure|reactivate)\b[^\n]{0,80}\b(account|profile|details|credentials|login)\b/i, 26],
        [/\b(login|log-?in|sign-?in)\s?(to|into|now|page|portal|to\sverify)\b/i, 24],
        [/\bconfirm\syour\s(?:payment|billing|card)\s(?:details|method|information)\b/i, 24],
        [/\b(?:unusual|suspicious|unauthori[sz]ed)\s(?:activity|login\w*|sign\s?in\w*|access)\b/i, 26],
        [/\bto\s(?:avoid|prevent)\b[^\n]{0,25}\b(?:suspension|closure|being\sclosed|blocked|deactivation)\b/i, 22],
        [P.otpAsk, 20], [P.links, 12], [P.genericGreeting, 6]
      ] },

    { id: 'spear_phishing', name: 'Spear phishing (targeted at you)', family: 'credential',
      how: 'The message uses your real name, order number or company details, so it feels personal and you lower your guard.',
      wants: 'A login, a payment, or a file opened — aimed specifically at you.',
      patterns: [
        [/\byour\s(?:order|invoice|application|appointment|delivery|subscription|leave|booking)\s(?:no\.?|number|#)?\s?[A-Z0-9-]{4,}\b/i, 26],
        [/\bas\s(?:you|we)\s(?:requested|discussed|agreed|mentioned)\b|\bref(?:erence)?:\s[A-Z0-9-]{3,}/i, 20],
        [/\bdear\s[A-Z][a-z]+(?:\s[A-Z][a-z]+)?\b/, 14],
        [P.otpAsk, 20], [P.links, 10]
      ] },

    { id: 'whaling', name: 'Whaling / CEO fraud', family: 'payment',
      how: 'The attacker pretends to be a senior boss or a big client and demands a confidential, urgent transfer with no questions asked.',
      wants: 'A wire or UPI transfer to their account, approved without the usual checks.',
      patterns: [
        [/\b(ceo|cfo|managing\sdirector|chairman|founder|director)\b/i, 26],
        [/\b(confidential|urgent\s(?:transfer|payment)|do\snot\sdiscuss|between\s(?:us|you\sand\sme)|keep\s(?:this|it)\squiet|only\syou|discreet\w*)\b/i, 28],
        [/\b(?:kindly|please)\s+(?:transfer|process|release|pay)\b[^\n]{0,60}\b(?:urgent\w*|immediately|now|today)\b/i, 24]
      ] },

    { id: 'bec_invoice', name: 'Invoice / payment-change fraud (BEC)', family: 'payment',
      how: 'An email claims your supplier changed their bank account. The real invoice gets paid into the scammer\'s account.',
      wants: 'You to pay a genuine invoice — into the wrong bank account.',
      patterns: [
        [/\b(?:new|updated?|changed)\s(?:our\s)?bank\s(?:details|account|information)\b|\bbank\s(?:details|account)\s(?:has\s|have\s)?changed\b/i, 34],
        [/\b(?:account\snumber|a\/c\s?no|beneficiary|ifsc|swift|micr|iban)\b/i, 24],
        [/\binvoice\b[^\n]{0,60}\b(?:attached|for\syour\srecords|due\sdate|outstanding|payment\sdue)\b/i, 22]
      ] },

    { id: 'fake_bank_kyc', name: 'Fake bank / KYC / account-blocked alert', family: 'credential',
      how: 'A message that looks like your bank says your KYC is pending or your account will be blocked today. The link opens a look-alike site that steals your login.',
      wants: 'Your internet-banking login, card details and OTP.',
      patterns: [
        [P.accountThreat, 34], [P.kyc, 30],
        [/\b(?:atm|card|debit|credit)\b[^\n]{0,25}\b(?:blocked|disabled|expired|restrict\w+)\b/i, 26],
        [/\b(?:bank\s+team|bank\s+alert|bank\s+update|-\s*(?:sbi|hdfc|icici|axis|kotak))\b/i, 10],
        [P.links, 12]
      ] },

    { id: 'smishing', name: 'Smishing (SMS phishing)', family: 'credential',
      how: 'A short SMS with a shortened or odd link. The link opens a fake site, a premium-rate service, or installs malware.',
      wants: 'A click on the link, then your details, your money, or a subscription charge.',
      patterns: [
        [/https?:\/\/[^\s]*\b(?:bit\.ly|tinyurl|t\.co|goo\.gl|cutt\.ly|rb\.gy|is\.gd|shorturl\.at)\b/i, 26],
        [/\b(?:click|tap)\s(?:the\s)?(?:link|below|here)\b/i, 18],
        [P.links, 14], [P.genericGreeting, 6]
      ] },

    { id: 'vishing', name: 'Vishing (fake callback / call centre)', family: 'credential',
      how: 'The message gets you on the phone with a fake "agent" who reads you codes, or guides you to a fake site while staying on the line.',
      wants: 'You on a call, reading out OTPs and card details.',
      patterns: [
        [/\b(?:call|dial|contact)\b[^\n]{0,40}\b(?:immediately|now|urgent\w*|helpline|toll[-\s]?free|within\s\d+)\b/i, 30],
        [/\bour\s(?:helpline|support|care)\s(?:number|no\.?|team|desk)\b/i, 24],
        [P.callback, 20], [P.otp, 20]
      ] },

    { id: 'quishing', name: 'Quishing (QR-code scam)', family: 'payment',
      how: 'A QR code is sent instead of a link. Scanning it either takes money from your account or opens a fake site — and QR codes cannot be checked before you scan.',
      wants: 'You to scan a code, then approve a payment or a fake login.',
      patterns: [
        [P.qr, 40],
        [/\bscan\b[^\n]{0,40}\b(?:pay|receive|claim|verify|download|to\sget)\b/i, 26]
      ] },

    { id: 'upi_fraud', name: 'UPI / payment-request fraud', family: 'payment',
      how: 'The scammer sends a "collect request" or a QR code dressed up as a refund. Approving it SENDS money from your account to them.',
      wants: 'You to approve a collect request, share a UPI PIN, or scan their QR.',
      patterns: [
        [/\b(?:collect|payment)\s?request\b|\bapprove\s(?:the\s)?(?:payment|request)\b/i, 34],
        [/\b(?:enter|share|tell|reply\s(?:with|back))\b[^\n]{0,40}\b(?:upi\s?pin|pin|password|otp)\b/i, 34],
        [/\byou\s(?:have\s)?received\s(?:a\s)?(?:payment|₹)/i, 26],
        [P.upi, 16]
      ] },

    { id: 'refund_scam', name: 'Fake refund / unclaimed money scam', family: 'payment',
      how: 'You are told a refund, lottery credit or unclaimed amount is waiting, but you must first pay a small "charge" or install an app.',
      wants: 'A "small fee" first — and your banking app after that.',
      patterns: [
        [/\b(?:refund|cashback|reimburse\w+|unclaimed\s(?:amount|refund|balance)|pending\s(?:refund|amount))\b/i, 30],
        [/\b(?:refundable|reimbursable)\s(?:fee|charge|amount)\b/i, 34],
        [/\b(?:pay|deposit|transfer)\b[^\n]{0,40}\b(?:to\s(?:receive|claim|release|process)|processing)\b/i, 26]
      ] },

    { id: 'otp_theft', name: 'OTP theft / SIM-swap setup', family: 'credential',
      how: 'The scammer is partway into your account and needs the code that just arrived on your phone. SIM-swap starts by collecting your details first.',
      wants: 'The OTP or PIN that proves you are you — the key to your account.',
      patterns: [
        [P.otpAsk, 44],
        [/\b(?:share|send|reply\s(?:with|back)|enter|provide)\b[^\n]{0,40}\b(?:code|otp|verification\scode)\b/i, 34],
        [/\b(?:our\s)?(?:executive|agent|team|representative)\b[^\n]{0,50}\b(?:code|otp|verify|verification)\b/i, 30],
        [/\b(?:sim\s?(?:swap|card)\s?(?:swap|fraud)?|port(?:ing)?\syour\snumber|new\s(?:sim|card)\sissued)\b/i, 34],
        [P.otp, 26]
      ] },

    { id: 'lottery_prize', name: 'Lottery / prize / giveaway scam', family: 'bait',
      how: 'You "win" something you never entered. To release it you pay "tax" or "fees", or you hand over ID and bank details.',
      wants: 'A fake fee, plus your ID and bank details.',
      patterns: [
        [P.prize, 40],
        [/\b(?:you\s(?:have\s)?won|congratulations!?|selected\sas\s(?:a\s)?winner|winner\s(?:announcement|selected))\b/i, 36],
        [/\b(?:claim|collect)\b[^\n]{0,30}\b(?:prize|reward|amount|money|ticket)\b/i, 26],
        [/\b(?:winning\s(?:no|number|code)|lucky\sdraw|draw\sno)\b/i, 26]
      ] },

    { id: 'job_scam', name: 'Job / work-from-home / task scam', family: 'bait',
      how: 'You are hired with no interview. Then you pay a "registration fee" or do fake tasks that show fake earnings you can never withdraw.',
      wants: 'An upfront fee, or a deposit you will never get back.',
      patterns: [
        [P.job, 40],
        [/\b(?:no\s(?:experience|interview|qualification)\s(?:needed|required)|join\snow\s(?:and|to)\s(?:start\s)?earn)\b/i, 30],
        [/\b(?:registration|onboarding|training)\s(?:fee|charge|amount)\b/i, 34],
        [/\b(?:earn|make|paid)\s(?:₹|rs\.?\s?|\$)\s?\d{2,}\b[^\n]{0,25}\b(?:per|a|\/)\s?(?:day|hour|month)\b/i, 30],
        [/\b(?:task|recharge|boost)\s(?:job|work|plan|cycle)\b/i, 26]
      ] },

    { id: 'investment_scam', name: 'Investment / crypto / trading-group scam', family: 'bait',
      how: 'You are added to a group where "experts" show huge profits. Small withdrawals build trust; then you invest big and cannot withdraw.',
      wants: 'Your capital — and a way into your bank or crypto wallet.',
      patterns: [
        [P.invest, 34],
        [/\bguaranteed\s(?:profit|returns?|income)\b/i, 34],
        [/\b\d{2,3}\s?%\s?(?:returns?|profit|annual|monthly|per\s?month|interest)\b/i, 30],
        [/\b(?:daily|weekly)\s(?:income|profit|earning)s?\b/i, 26],
        [/\bwithdraw\w*\b[^\n]{0,50}\b(?:cannot|can'?t|unable|pending|fee|charge)\b/i, 30]
      ] },

    { id: 'romance_scam', name: 'Romance scam', family: 'trust',
      how: 'Someone online falls in love fast, always with a reason not to video call, then hits a crisis: a medical bill, a stuck parcel, a flight home.',
      wants: 'Money "for an emergency", and access to your wallet or accounts.',
      patterns: [
        [P.romance, 34],
        [/\b(?:sweetheart|darling|my\s?love|fallen\sfor\syou|forever\s?yours|soulmate)\b/i, 24],
        [/\b(?:account\s(?:is\s|has(?:\sbeen)?\s)?(?:frozen|blocked)|i\s(?:need|must|have\sto)\s?.{0,20}(?:come\s?to\syou|meet\syou|see\syou|fly))\b/i, 18],
        [/\b(?:i\s(?:can'?t|cannot)\s(?:wait\s)?to\s(?:meet|see\syou)|my\sdear)\b/i, 18],
        [/\b(?:stranded|stuck)\s(?:abroad|at\sthe\sairport|in\s(?:a\s)?(?:country|city))|medical\semergency|need\s(?:some\s)?money\s(?:to|for)\s(?:come|return|travel|flight)\b/i, 26],
        [/\b(?:please\shelp|i\s?need)\b[^\n]{0,35}\b(?:\$|usd|money|amount|fee|fees)\b/i, 20]
      ] },

    { id: 'sextortion', name: 'Sextortion (blackmail with a fake "intimate video")', family: 'trust',
      how: 'You are told a video call of you was recorded and will be shared with family unless you pay immediately. The video is usually fake or edited.',
      wants: 'An immediate payment — and more payments after that.',
      patterns: [
        [P.sextortion, 44],
        [/\b(?:we|I)\s(?:have\s)?(?:recorded|captured|screen\s?recorded)\b[^\n]{0,40}\b(?:video|call|you)\b/i, 40],
        [/\b(?:send|pay)\b[^\n]{0,50}\b(?:otherwise|or\s(?:else)?|within)\b/i, 36]
      ] },

    { id: 'tech_support', name: 'Tech-support / remote-access scam', family: 'credential',
      how: 'A pop-up or message says your device is infected or your subscription renewed. The "engineer" asks you to install remote-control software, then moves your money.',
      wants: 'Control of your device, plus the payment they claim you owe.',
      patterns: [
        [P.remoteAccess, 40],
        [/\byour\s(?:device|computer|pc|phone)\b[^\n]{0,40}\b(?:infected|compromised|virus|has\sbeen\sinfected)\b|\bvirus\s(?:detected|alert|found)\b/i, 34],
        [/\b(?:windows|apple|microsoft|google|amazon)\s(?:support|security|team|helpdesk)\b/i, 24],
        [/\b(?:subscription\s(?:renewed|expired|about\sto\sexpire)|renew\syour\ssubscription)\b/i, 24]
      ] },

    { id: 'delivery_courier', name: 'Delivery / courier / customs fee scam', family: 'payment',
      how: 'A parcel is "held" for a small fee or a fake customs charge; the tracking link steals your details. Sometimes you pay for a package you never ordered.',
      wants: 'A small payment, plus your address and card details.',
      patterns: [
        [P.delivery, 34],
        [/\b(?:parcel|package|shipment|order)\b[^\n]{0,60}\b(?:hold|held|pending|stuck|undelivered|delivery\sfailed|blocked|awaiting)\b/i, 32],
        [/\b(?:pay|transfer|deposit)\b[^\n]{0,40}\b(?:customs|clearance|delivery|shipping|handling|storage)\s?(?:fee|charge|charges)\b/i, 38],
        [/\b(?:reschedule|re-?attempt|delivery\sattempt(?:ed)?\sfailed|attempted\sdelivery)\b/i, 24]
      ] },

    { id: 'gov_impersonation', name: 'Government / police / tax impersonation (incl. digital arrest)', family: 'authority',
      how: 'You are told your parcel contains illegal items or your tax refund is pending, and "officers" keep you on a video call while you transfer money to a "safe account".',
      wants: 'Money moved to a "safe" account, or your ID and bank details.',
      patterns: [
        [P.govThreat, 40],
        [/\b(?:case\s(?:has\s|is\s)?been\sfiled|registered\scomplaint|summons|warrant|fir\sregistered)\b/i, 30],
        [/\b(?:safe|verified|government|frozen)\saccount\b[^\n]{0,40}\b(?:transfer|deposit|send|move)\b/i, 34],
        [/\b(?:narcotics|cyber\scell|\bcid\b|enforcement\sdirectorate|ed\snotice|customs\sdepartment)\b/i, 30],
        [P.threat, 16]
      ] },

    { id: 'utility_scam', name: 'Electricity / gas / utility disconnection scam', family: 'authority',
      how: 'A warning says your power or gas will be disconnected in hours unless you pay through a QR code or the number they gave you.',
      wants: 'A quick payment through an untraceable channel.',
      patterns: [
        [P.utility, 40],
        [/\b(?:disconnect\w*|suspend\w*)\b[^\n]{0,50}\b(?:in\s\d+\s(?:hours?|mins?|minutes?)|today|immediately|tonight)\b/i, 36],
        [/\b(?:pay|scan|call)\b[^\n]{0,50}\b(?:avoid|prevent|stop)\s(?:disconnection|discontinu\w+|cut[-\s]?off)\b/i, 34]
      ] },

    { id: 'loan_scam', name: 'Loan-app scam and harassment', family: 'payment',
      how: 'A "loan approved" message leads to an app that demands huge interest, uploads your contacts and photos, then threatens to share them.',
      wants: 'Your contacts and photos for blackmail, plus inflated repayments.',
      patterns: [
        [P.loan, 36],
        [/\binstall\b[^\n]{0,40}\b(?:app|application)\b[^\n]{0,40}\bloan\b|\bloan\b[^\n]{0,25}\bapproved\sinstantly\b/i, 34],
        [/\b(?:share|upload|access|allow)\b[^\n]{0,40}\b(?:contacts|photos|gallery|camera)\b/i, 30]
      ] },

    { id: 'malware_delivery', name: 'Malware delivery (bad attachment or link)', family: 'malware',
      how: 'An attachment or link installs software that logs your keystrokes, steals banking sessions, or locks your files for ransom.',
      wants: 'A file opened or a download run on your device.',
      patterns: [
        [/\.(?:exe|scr|bat|cmd|js|vbs|wsf|msi|jar|apk|ps1|hta)\b/i, 40],
        [/\b(?:enable\s(?:macros|content)|allow\sediting|run\s(?:the\s)?attached|open\s(?:the\s)?attachment)\b/i, 38],
        [/\bpassword\s+(?:is|was)?[\s:]{0,3}["']?([a-z0-9]{3,})["']?/i, 32],
        [/\.(?:zip|rar|7z|docm|xlsm|pptm|iso)\b/i, 20]
      ] },

    { id: 'brand_impersonation', name: 'Brand impersonation (Netflix, Amazon, banks...)', family: 'brand',
      how: 'A well-known brand name and tone are copied. The link domain is close but not the real one — one letter changed, an extra word added.',
      wants: 'Your saved card, your login, or a "fee" to release something.',
      patterns: [
        [/\byour\s(?:netflix|amazon|paypal|instagram|whatsapp|google|apple|flipkart)\s(?:account|subscription|profile|order|membership)\b/i, 30],
        [/\b(?:verify|secure|reactivate|update|confirm|restore)\b[^\n]{0,60}\b(?:your\s)?(?:netflix|amazon|paypal|subscription|account\sstatus)\b/i, 30],
        [/\b(?:could\snot\sbe\s(?:charged|processed)|\bpayment\s(?:details|method|card)\b[^\n]{0,40}\b(?:suspended|suspension|closed|blocked|expired))\b/i, 26],
        [/\b(?:prime\svideo|apple\sid|google\saccount|instagram\ssecurity|whatsapp\s(?:business|verification))\b/i, 26]
      ] }
  ];

  /* Risk levels: colour + icon + word (never colour alone). */
  SCAM.LEVELS = [
    { id: 'safe', label: 'Safe', icon: '\u2713', min: 0, max: 24, color: '#2E7D51',
      verdict: 'Nothing suspicious stood out. Still, never share passwords or OTPs.' },
    { id: 'low', label: 'Low risk', icon: '!', min: 25, max: 49, color: '#8A6D1F',
      verdict: 'A few odd details. Slow down and double-check the sender before you act.' },
    { id: 'medium', label: 'Medium risk', icon: '\u26A0', min: 50, max: 74, color: '#A85D14',
      verdict: 'This looks suspicious. Do not click or reply — check with the company directly.' },
    { id: 'high', label: 'High risk', icon: '\u26A0', min: 75, max: 89, color: '#B23B2E',
      verdict: 'This looks like a scam. Do not click, do not reply, and warn your family.' },
    { id: 'critical', label: 'Critical', icon: '\u2715', min: 90, max: 100, color: '#8E1F1B',
      verdict: 'Do not click. This is very likely a scam.' }
  ];

  SCAM.levelFor = function (score) {
    for (var i = 0; i < SCAM.LEVELS.length; i++) {
      if (score <= SCAM.LEVELS[i].max) return SCAM.LEVELS[i];
    }
    return SCAM.LEVELS[SCAM.LEVELS.length - 1];
  };

  /* Per-family advice feeds the "What to do now" checklist. */
  SCAM.ATTACK_ADVICE = {
    credential: ['Do not open the link and do not enter any details.',
      'If you already entered details, change your password now and lock your card from your bank app.',
      'Tell your bank and keep this message as evidence.'],
    payment: ['Do not approve any UPI request and do not scan the QR code.',
      'If you already paid, call your bank immediately and report it on cybercrime.gov.in or 1930. The first hour matters most.',
      'Note the number, UPI ID and time of payment.'],
    bait: ['Do not pay any "fee" to receive a prize, job or refund — real ones never charge you.',
      'Do not share ID documents or bank details.',
      'If you already paid, contact your bank and report on 1930.'],
    trust: ['Stop all contact with this person. Do not send photos, money or documents.',
      'Do not install any app they suggest and do not share your screen.',
      'Tell someone you trust and report the profile in the app.'],
    authority: ['Real police, tax and utility departments never demand payment over SMS, QR code or WhatsApp.',
      'Call the official number printed on your bill, or from the department\'s own website.',
      'Report it on cybercrime.gov.in or 1930.'],
    malware: ['Do not open the attachment or download the file.',
      'Run a security scan if you already opened it.',
      'Change your passwords from a different, clean device.'],
    brand: ['Open the company\'s app, or type their website yourself — never use the link in the message.',
      'Read the full web address letter by letter for extra or missing letters.',
      'Report the message as phishing in your mail app.']
  };

  /* Top 10 tricks for the Learn section */
  SCAM.LEARN = [
    { title: 'The "your account will be blocked today" text',
      body: 'Banks do not suspend accounts by SMS with a link. They ask you to log in through the official app.',
      example: 'Dear Customer, your SBI account will be BLOCKED in 2 hours. Update KYC: http://sbi-kyc-verify.info' },
    { title: 'The OTP "verification" request',
      body: 'No bank, wallet or company will ever ask you to read out a code that just arrived on your phone.',
      example: 'Your login code is 449128. Share this OTP with our agent to complete verification.' },
    { title: 'The look-alike web address',
      body: 'Scammers change one letter (paypa1.com) or add a word (secure-login-paypal.com). Read it letter by letter.',
      example: 'Login now: https://paypal-secure.verify-login.in/account' },
    { title: 'The QR code that pays money out',
      body: 'To RECEIVE money you never scan a code — you show yours. A "refund QR" is a payment you make.',
      example: 'Scan this QR to receive your refund of Rs.4,999 within 5 minutes.' },
    { title: 'The easy-money job',
      body: 'A job that hires instantly, pays per "task" and asks for a recharge fee is an investment scam in disguise.',
      example: 'Congratulations! You are hired. Pay the Rs.250 registration fee to start earning Rs.3,500 daily.' },
    { title: 'The boss who wants a quiet transfer',
      body: 'Real approvals follow a process. Pressure to transfer secretly, urgently and quietly is BEC fraud.',
      example: 'I am in a meeting. Kindly transfer Rs.85,000 to the vendor now. Keep this between us.' },
    { title: 'The "digital arrest" video call',
      body: 'Police never arrest people over a call or hold them on video while money moves. Hang up.',
      example: 'Your parcel has illegal contents. Join this video call or your account will be frozen today.' },
    { title: 'The remote-access app',
      body: 'AnyDesk or TeamViewer codes are for trusted IT support only. With one, a stranger can operate your phone.',
      example: 'Our engineer will fix it. Install AnyDesk and share the 9-digit code with us.' },
    { title: 'The too-fast romance with a crisis',
      body: 'Love that arrives in days, avoids video calls, then needs money for stuck surgery or a flight — it is scripted.',
      example: 'My love, my flight is stuck and I need $900 for airport fees. Please help, I repay you tomorrow.' },
    { title: 'The lottery you never entered',
      body: 'A prize always needs your "tax" or "fee" first. That fee is the scam — there is no prize.',
      example: 'You have won Rs.25,00,000 in the lucky draw! Pay Rs.8,500 processing fee to claim.' }
  ];
})(typeof globalThis !== 'undefined' ? globalThis : this);
