/* ============================================================================
 * email.js — Email-only checks: sender, display name, reply-to, authentication
 * headers (SPF / DKIM / DMARC) and suspicious attachments.
 *
 * Every check returns { id, label, explain, weight, evidence[] } so scoring.js
 * can treat it exactly like a signal (fully explainable points).
 * ==========================================================================*/
(function (g) {
  'use strict';
  var SCAM = (g.SCAM = g.SCAM || {});
  var lev = SCAM.lev;

  /* Parse 'Name <user@host>' or a bare address */
  function parseAddress(value) {
    if (!value) return null;
    var v = value.trim();
    var m = v.match(/^(.*)<([^>]+)>\s*$/);
    var name = '', addr = '';
    if (m) { name = m[1].trim().replace(/^"|"$/g, ''); addr = m[2].trim(); }
    else if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) { addr = v; }
    else { name = v; }
    return { name: name, addr: addr.toLowerCase(), host: addr.split('@')[1] || '' };
  }
  SCAM.parseAddress = parseAddress;

  /* Find the header line that starts with `key` (case-insensitive) */
  function headerValue(headers, key) {
    if (!headers) return '';
    var re = new RegExp('^' + key + '\\s*:\\s*(.+)$', 'im');
    var m = headers.match(re);
    if (!m) return '';
    /* unfold continuation lines */
    return headers.replace(/\r?\n[ \t]+/g, ' ').match(re)[1].trim();
  }
  SCAM.headerValue = headerValue;

  /* Which brand (if any) does a domain or name claim to be? */
  function claimedBrand(text) {
    if (!text) return null;
    var t = text.toLowerCase();
    for (var i = 0; i < SCAM.BRANDS.length; i++) {
      var b = SCAM.BRANDS[i];
      for (var j = 0; j < b.words.length; j++) {
        if (t.indexOf(b.words[j]) !== -1) return b;
      }
    }
    return null;
  }
  SCAM.claimedBrand = claimedBrand;

  /* Strip a common mail host so 'paypal.support@secure-mail.com' vs host compare */
  var FREE_HOSTS = ['gmail.com', 'yahoo.com', 'yahoo.co.in', 'outlook.com', 'hotmail.com', 'rediffmail.com', 'aol.com', 'protonmail.com', 'icloud.com'];

  /* ---- main check ------------------------------------------------------ */
  SCAM.checkEmail = function (input) {
    var out = [];
    var sender = parseAddress(input.sender || '');
    var replyTo = parseAddress(input.replyTo || '');
    var headers = input.headers || '';
    var allText = ((input.sender || '') + ' ' + (input.subject || '') + ' ' + (input.body || '')).trim();
    var lower = allText.toLowerCase();

    /* 1. Display name claims a brand, but the domain is not the brand's */
    if (sender && sender.name && sender.addr) {
      var brand = claimedBrand(sender.name) || claimedBrand(sender.addr);
      if (brand) {
        var hostOk = brand.domains.some(function (d) {
          return sender.host === d || sender.host.slice(-(d.length + 1)) === '.' + d || sender.host === d.replace(/^www\./, '');
        });
        if (!hostOk) {
          out.push({
            id: 'sender_brand_mismatch',
            label: 'Sender pretends to be ' + brand.name,
            weight: 22,
            explain: 'The name says ' + brand.name + ', but the email really comes from ' + sender.host + '. ' + brand.name + ' does not send mail from there.',
            evidence: [input.sender]
          });
        }
      }
    }

    /* 1b. Brand word smuggled INTO the sending domain (help@netflix-login.evil.net)
       — the domain is not the brand's own, even if the label looks convincing. */
    if (sender && sender.host) {
      var hostBrand = claimedBrand(sender.name) ? null : claimedBrand(sender.host);
      if (hostBrand) {
        var real = hostBrand.domains.some(function (d) {
          return sender.host === d || sender.host.slice(-(d.length + 1)) === '.' + d;
        });
        if (!real) {
          out.push({
            id: 'sender_brand_in_host', label: 'Brand name hidden inside a fake address', weight: 18,
            explain: 'The brand appears in the address (' + sender.host + '), but the real owner is not ' + hostBrand.name + '. Famous names are placed in front of a different domain to trick you.',
            evidence: [sender.addr]
          });
        }
      }
    }

    /* 2. Look-alike / spoofed sending domain (paypa1.com, hdfcbnak.net) */
    if (sender && sender.host) {
      var la = null;
      SCAM.BRANDS.forEach(function (b) {
        b.domains.forEach(function (d) {
          if (la || sender.host === d) return;
          var reg = sender.host.split('.').slice(-2).join('.');
          if (lev(reg, d) <= 2 && reg !== d) {
            la = { brand: b, why: 'domain "' + reg + '" is only a couple of characters away from ' + d };
          }
        });
      });
      if (la) {
        out.push({
          id: 'lookalike_domain', label: 'Look-alike sender domain', weight: 22,
          explain: 'The sending ' + la.why + '. This is how fake addresses are disguised.',
          evidence: [sender.addr]
        });
      }
      /* Free mail address while the message claims to be a company */
      var claimed = claimedBrand(allText);
      if (claimed && FREE_HOSTS.indexOf(sender.host) !== -1 && !claimed.words.some(function (w) { return sender.addr.indexOf(w) !== -1; })) {
        out.push({
          id: 'free_mail_corp', label: 'Company message sent from free mail', weight: 14,
          explain: 'A ' + claimed.name + ' notice arriving from a ' + sender.host + ' address is a red flag — real companies mail from their own domain.',
          evidence: [sender.addr]
        });
      }
      /* Deep subdomain trick: security@paypal.com.evil.xyz */
      if (sender.host.split('.').length >= 4) {
        out.push({
          id: 'deep_sender_host', label: 'Sender address has many parts', weight: 12,
          explain: 'The real owner of this address is "' + sender.host.split('.').slice(-3).join('.') + '", not what appears at the start.',
          evidence: [sender.host]
        });
      }
      /* Domain ending often used by scammers (.tk, .top, .zip, ...) */
      var senderTld = sender.host.split('.').slice(-1)[0] || '';
      if (senderTld && SCAM.SUSPICIOUS_TLDS.indexOf(senderTld) !== -1) {
        out.push({
          id: 'sender_tld', label: 'Sender domain ends in .' + senderTld, weight: 8,
          explain: 'The sending address ends in .' + senderTld + ', an ending frequently used for disposable scam mailboxes.',
          evidence: [sender.host]
        });
      }
    }

    /* 3. Reply-To does not match the From address */
    if (sender && replyTo && replyTo.addr && sender.addr && replyTo.addr !== sender.addr) {
      var sameHost = replyTo.host && sender.host && (replyTo.host === sender.host);
      if (!sameHost) {
        out.push({
          id: 'replyto_mismatch', label: 'Replies go somewhere else', weight: 16,
          explain: 'If you hit Reply, your answer goes to ' + replyTo.addr + ' instead of the sender — a classic sign of a hijacked or faked sender.',
          evidence: [replyTo.addr]
        });
      }
    }

    /* 4. SPF / DKIM / DMARC hints from pasted headers */
    if (headers) {
      var spf = headerValue(headers, 'Received-SPF');
      var auth = headerValue(headers, 'Authentication-Results');
      var dkim = /dkim=(pass|fail|none|permerror)/i.exec(auth || '');
      var spfRes = /spf=(pass|fail|none|permerror)/i.exec(auth || '') || /(:|\s)(pass|fail|none)\s/i.exec(spf || '');
      var dmarc = /dmarc=(pass|fail|none|permerror)/i.exec(auth || '');

      var spfStatus = spfRes ? spfRes[1] || spfRes[2] : '';
      if (/fail/i.test(spfStatus)) {
        out.push({ id: 'spf_fail', label: 'SPF check failed', weight: 14,
          explain: 'The mail servers say this sender is not allowed to use that domain — the address is forged.',
          evidence: [spf || auth.slice(0, 80)] });
      } else if (dkim && /dkim=fail/i.test(dkim[0])) {
        out.push({ id: 'dkim_fail', label: 'DKIM signature failed', weight: 14,
          explain: 'The digital signature on this email does not match — the message was altered or faked.',
          evidence: [auth.slice(0, 90)] });
      } else if (dmarc && /dmarc=fail/i.test(dmarc[0])) {
        out.push({ id: 'dmarc_fail', label: 'DMARC check failed', weight: 14,
          explain: 'The domain owner says this message is not genuine.',
          evidence: [auth.slice(0, 90)] });
      }
      if (/dkim=none/i.test(auth || '') && /spf=(?:none|fail)/i.test(auth || '')) {
        out.push({ id: 'auth_missing', label: 'No email authentication found', weight: 7,
          explain: 'Nothing proves the sender really owns that domain, so the name can be faked easily.',
          evidence: ['No SPF/DKIM pass found in the pasted headers'] });
      }
      /* Alignment: envelope sender domain vs From domain */
      var envFrom = headerValue(headers, 'Return-Path') || headerValue(headers, 'Envelope-From');
      var envAddr = parseAddress(envFrom.replace(/^.*</, '<').indexOf('<') === 0 ? envFrom : envFrom);
      if (envAddr && envAddr.host && sender && sender.host && envAddr.host !== sender.host &&
          !/(\+|bounce)/.test(envAddr.addr)) {
        out.push({ id: 'envelope_mismatch', label: 'Envelope sender differs from From', weight: 8,
          explain: 'The hidden return path (' + envAddr.host + ') is not the displayed sender — check before replying.',
          evidence: [envAddr.addr] });
      }
    }

    /* 5. Suspicious attachments named in subject/body */
    var attRe = /[\w\s-]{2,60}\.(exe|scr|bat|cmd|js|vbs|wsf|msi|jar|apk|ps1|hta|docm|xlsm|pptm|zip|rar|iso)(?![\w.])/gi;
    var found = [], m;
    while ((m = attRe.exec(allText)) && found.length < 6) found.push(m[0].trim());
    if (found.length) {
      var dangerous = found.filter(function (f) { return /\.(exe|scr|bat|cmd|js|vbs|wsf|msi|jar|apk|ps1|hta)$/i.test(f); });
      var doubleExt = found.filter(function (f) { return /(?:pdf|docx?|xlsx?|txt|jpg|png|invoice|scan)\.[a-z0-9]+$/i.test(f) && /\.(js|exe|vbs|scr|bat|cmd|apk|hta)$/i.test(f); });
      out.push({
        id: 'bad_attachment',
        label: dangerous.length ? 'Dangerous attachment type' : 'Risky compressed attachment',
        weight: dangerous.length ? 26 : 12,
        explain: dangerous.length
          ? 'Files like ' + dangerous[0] + ' can install software the moment they are opened. Never open them.'
          : 'Compressed or macro-enabled files are often used to hide malware. Only open if you truly expect it.',
        evidence: found
      });
      if (doubleExt.length) {
        out.push({ id: 'double_extension', label: 'Trick file name (double extension)', weight: 16,
          explain: 'The file pretends to be a document but is really ' + doubleExt[0].split('.').pop() + '.',
          evidence: doubleExt });
      }
    }
    /* "Password protected zip" + password in the message defeats mail scanners */
    if (/password[-\s]?protected/i.test(allText) && /password\s*(is|:)\s*\S+/i.test(allText)) {
      out.push({ id: 'pw_zip', label: 'Password-protected file with password in the mail', weight: 14,
        explain: 'Sending the password in the same email hides the file from security scanners — a well-known malware trick.',
        evidence: ['password protected attachment'] });
    }

    /* 6. Subject/body: generic reply-to style urgency handled by signals.
       Here: display name only (no address at all) — spoofed sender. */
    if (input.sender && !sender.addr && input.sender.indexOf('@') === -1 && input.sender.trim().length > 1) {
      out.push({ id: 'no_addr', label: 'No real email address given', weight: 8,
        explain: 'The sender field has a name but no usable address, so the true origin is hidden.',
        evidence: [input.sender] });
    }

    return out;
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
