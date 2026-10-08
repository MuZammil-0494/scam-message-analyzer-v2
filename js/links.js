/* ============================================================================
 * links.js — Extracts and inspects every URL in a message.
 *
 * Each flag adds points to the score (see scoring.js) and is shown in the
 * "Link inspection" panel with the real destination and why it is odd.
 * ==========================================================================*/
(function (g) {
  'use strict';
  var SCAM = (g.SCAM = g.SCAM || {});

  var URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"')\]]+/gi;
  var BARE_RE = /\b(?:[a-z0-9-]+\.)+(?:com|in|net|org|co|io|me|xyz|top|club|click|link|win|loan|buzz|tk|ml|cf|ga|gq|info|biz|online|site|store|tech|live|icu|cc|pw|us|uk|ca|au|de|ru|dev|app|gov|edu)(?:\.[a-z]{2,2})?(?:\/[^\s<>"')\]]*)?/gi;

  /* Levenshtein distance, capped (cheap look-alike test) */
  function lev(a, b) {
    a = a.toLowerCase(); b = b.toLowerCase();
    if (Math.abs(a.length - b.length) > 3) return 99;
    var prev = [], cur = [], i, j;
    for (j = 0; j <= b.length; j++) prev[j] = j;
    for (i = 1; i <= a.length; i++) {
      cur[0] = i;
      for (j = 1; j <= b.length; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur.slice();
    }
    return prev[b.length];
  }
  SCAM.lev = lev;

  /* Pull every link out of a message (with an index so we can show order) */
  function extractUrls(text) {
    var out = [], seen = {}, m;
    var re = new RegExp(URL_RE.source + '|' + BARE_RE.source, 'gi');
    while ((m = re.exec(text)) !== null) {
      var raw = m[0].replace(/[.,;:!?)\]}]+$/, '');
      var key = raw.toLowerCase();
      if (seen[key]) continue;
      seen[key] = true;
      out.push({ raw: raw, index: m.index });
      if (out.length > 25) break;
    }
    return out;
  }
  SCAM.extractUrls = extractUrls;

  /* Shape of a hostname: registered domain + tld + subdomains */
  function parseHost(hostname) {
    var host = hostname.toLowerCase().replace(/^www\./, '');
    var parts = host.split('.');
    var tld = parts.length > 1 ? parts[parts.length - 1] : '';
    var second = parts.length > 2 ? parts[parts.length - 2] : '';
    var registered = parts.slice(-2).join('.');
    return { host: host, parts: parts, tld: tld, registered: registered, second: second, subs: parts.slice(0, -2) };
  }

  /* Is the host an IP address, or an IP with a port/path? */
  function isIpHost(host) {
    return /^\d{1,3}(\.\d{1,3}){3}(:\d+)?(?=\/|$)/.test(host) ||
      /^\[[0-9a-f:]+\]/i.test(host);
  }

  /* Homograph / punycode: xn-- labels, or mixed scripts (Cyrillic + Latin) */
  function homographFlags(host) {
    var flags = [];
    if (/[a-z0-9-]--/i.test(host) || /xn--/i.test(host)) {
      flags.push('Uses "punycode" (xn--) — letters can look like another alphabet, so "раypal.com" can mimic "paypal.com".');
    }
    var hasLatin = /[a-z]/i.test(host);
    var hasOther = /[Ѐ-ӿͰ-Ͽ一-鿿]/.test(host);
    if (hasLatin && hasOther) {
      flags.push('Mixes letter alphabets in one address — a classic trick to fake a familiar brand name.');
    }
    return flags;
  }

  /* Check a brand word appearing inside a *different* domain */
  function brandMismatch(host, textLower) {
    var hits = [];
    SCAM.BRANDS.forEach(function (b) {
      var inHost = b.words.some(function (w) { return host.indexOf(w) !== -1; });
      var inText = b.words.some(function (w) { return textLower.indexOf(w) !== -1; });
      if (inText && !inHost) {
        // text mentions brand but link domain does not carry it
        var nearBrand = SCAM.BRANDS.some(function (b2) {
          return b2.words.some(function (w) { return host.indexOf(w) !== -1; });
        });
        if (!nearBrand) hits.push(b);
      }
    });
    return hits;
  }

  /* Look-alike registered domain vs known brand domains (paypa1.com, g00gle.com)
   * plus brand words smuggled into hosts (paypal-secure.verify-login.in). */
  function lookalikeBrand(host) {
    var found = null;
    SCAM.BRANDS.forEach(function (b) {
      if (found) return;
      /* 1) distance match on the registered domain */
      var reg = host.split('.').slice(-2).join('.');
      var realHost = b.domains.some(function (d) {
        return host === d || host.slice(-(d.length + 1)) === '.' + d;
      });
      b.domains.forEach(function (d) {
        if (found || realHost) return;
        if (host === d) return;
        if (lev(reg, d) <= 2 && reg !== d) {
          found = { brand: b, why: 'Looks almost identical to ' + d + ' — a letter was changed or swapped.' };
        }
      });
      /* 2) brand word placed in front of a different domain */
      if (!found && !realHost) {
        var hasWord = b.words.some(function (w) { return host.indexOf(w) !== -1; });
        if (hasWord) {
          found = {
            brand: b,
            why: 'The brand name is placed inside the address, but the real owner is not ' + b.domains[0] + '.'
          };
        }
      }
    });
    return found;
  }

  /* Full inspection of one URL. Returns { url, host, ok, flags[], score, notes[] } */
  function inspectUrl(raw, text) {
    var flags = [], score = 0, notes = [];
    var withScheme = /^(https?:|www\.)/i.test(raw) ? raw : 'http://' + raw;
    var parsed;
    try { parsed = new URL(withScheme); } catch (e) {
      return { url: raw, host: '(could not read address)', flags: ['This address could not be read properly — treat it as unsafe.'], score: 25, notes: [], scheme: '' };
    }
    var host = parsed.hostname;
    var info = parseHost(host);
    var scheme = parsed.protocol.replace(':', '');

    if (scheme === 'http') {
      score += 8;
      flags.push('Uses plain http:// instead of https:// — anything you type can be intercepted.');
      notes.push('No encryption on this connection.');
    }
    if (isIpHost(host)) {
      score += 18;
      flags.push('The address is a raw IP number instead of a real company name.');
      notes.push('Real services do not link you to a bare IP address.');
    }
    SCAM.SHORTENERS.forEach(function (s) {
      if (info.host === s || info.host.indexOf(s + '/') !== -1) {
        score += 14;
        flags.push('Hidden behind the link shortener ' + s + ' — you cannot see where it really goes.');
        notes.push('Shortened link: destination is hidden.');
      }
    });
    if (info.tld && SCAM.SUSPICIOUS_TLDS.indexOf(info.tld) !== -1) {
      score += 12;
      flags.push('Ends in .' + info.tld + ' — a domain ending often abused by scammers.');
      notes.push('Suspicious domain ending .' + info.tld + '.');
    }
    if (info.subs.length >= 4) {
      score += 10;
      flags.push('Has ' + info.subs.length + ' sub-parts before the domain (' + info.subs.slice(0, 3).join('.') + '...) — long prefixes hide the real owner.');
      notes.push('Deeply nested subdomain.');
    }
    homographFlags(info.host).forEach(function (f) { score += 16; flags.push(f); notes.push('Letter-lookalike address.'); });

    var la = lookalikeBrand(info.host);
    if (la) {
      score += 22;
      flags.push('Looks like ' + la.brand.name + ' but is not ' + la.brand.domains[0] + ' — ' + la.why);
      notes.push('Possible fake ' + la.brand.name + ' address.');
    }

    /* Brand mentioned in the text but missing from the link domain */
    var mismatches = brandMismatch(info.host, (text || '').toLowerCase());
    if (mismatches.length && !la) {
      var names = mismatches.slice(0, 2).map(function (b) { return b.name; }).join(', ');
      score += 14;
      flags.push('The message talks about ' + names + ', but this link is not on their real website.');
      notes.push('Link does not match the brand mentioned.');
    }

    /* Numeric-heavy host (paypal-48291.com style) */
    if (/\d{3,}/.test(info.registered.replace(/\.(com|in|net|org|co|info|biz|xyz|top)\b/, ''))) {
      score += 8;
      flags.push('The address is stuffed with random numbers, which real company sites do not do.');
      notes.push('Random numbers in the domain.');
    }

    if (info.host.indexOf('-') !== -1 && (la || mismatches.length)) {
      score += 6;
      flags.push('Uses hyphens together with a brand name — a common way to fake an official address.');
      notes.push('Hyphenated brand-looking address.');
    }

    var trusted = ['google.com', 'github.com', 'wikipedia.org', 'gov.in', 'gov.uk', 'apple.com', 'microsoft.com'];
    if (trusted.some(function (t) { return info.registered === t || info.host === t; })) score = Math.max(0, score - 12);

    score = Math.max(0, Math.min(45, score));
    return {
      url: raw,
      href: parsed.href,
      host: info.host,
      registered: info.registered,
      tld: info.tld,
      scheme: scheme,
      flags: flags,
      notes: notes,
      score: score,
      safe: flags.length === 0
    };
  }
  SCAM.inspectUrl = inspectUrl;

  SCAM.inspectAllUrls = function (text) {
    return extractUrls(text).map(function (u) { return inspectUrl(u.raw, text); });
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
