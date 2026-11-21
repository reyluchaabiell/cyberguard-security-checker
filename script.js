/**
 * CyberGuard — Website Security Assessment Tool
 * Vanilla ES6+, no dependencies beyond Tailwind CSS (CDN).
 * All DNS lookups use Google DNS-over-HTTPS (json mode).
 * @version 1.0.0
 */

'use strict';

/* ==========================================================================
   CONFIG
   ========================================================================== */

const CONFIG = {
  API_ENDPOINTS: {
    DOH: 'https://dns.google/resolve',
  },

  DNS_TIMEOUT_MS: 8000,
  FETCH_TIMEOUT_MS: 10000,

  /** Weight table for the risk scoring engine. Keys must match check IDs. */
  SECURITY_WEIGHTS: {
    https_availability:     20,
    hsts:                   10,
    csp:                    15,
    x_frame_options:         5,
    x_content_type_options:  5,
    referrer_policy:         5,
    permissions_policy:      5,
    spf:                    10,
    dmarc:                  15,
    dkim:                   10,
  },

  DKIM_COMMON_SELECTORS: ['google', 'selector1', 'selector2', 'default', 'k1'],
};

/* DNS Record type numbers */
const DNS_TYPE = { A: 1, AAAA: 28, MX: 15, NS: 2, TXT: 16, CNAME: 5 };

/* Result status constants */
const STATUS = {
  PASS:    'pass',
  WARN:    'warn',
  FAIL:    'fail',
  INFO:    'info',
  UNKNOWN: 'unknown',
};

/* ==========================================================================
   DOMAIN VALIDATOR
   ========================================================================== */

/**
 * Normalises a user-supplied domain string.
 * - Strips leading/trailing whitespace.
 * - Removes protocol prefixes (http://, https://, ftp://, etc.).
 * - Removes trailing slashes and paths.
 * - Lowercases the result.
 * @param {string} raw
 * @returns {string}
 */
function normalizeDomain(raw) {
  if (typeof raw !== 'string') return '';
  let d = raw.trim().toLowerCase();
  // Block dangerous URL schemes before stripping
  if (/^(javascript|data|file|vbscript):/.test(d)) return '';
  // Strip protocol
  d = d.replace(/^[a-z][a-z0-9+\-.]*:\/\//, '');
  // Strip path, query, fragment
  d = d.split('/')[0].split('?')[0].split('#')[0];
  // Strip port
  d = d.replace(/:\d+$/, '');
  return d;
}

/**
 * Validates a normalised domain name.
 * Returns null on success, or an error string on failure.
 * @param {string} domain
 * @returns {string|null}
 */
function validateDomain(domain) {
  if (!domain || domain.length === 0) return 'Please enter a domain name.';
  if (domain.length > 253) return 'Domain name too long (max 253 characters).';

  // Block dangerous schemes that may survive normalisation
  if (/^(javascript|data|file|vbscript):/.test(domain)) {
    return 'Invalid domain: URL schemes are not allowed.';
  }

  // Must contain at least one dot (TLD required)
  if (!domain.includes('.')) return 'Domain must include a TLD (e.g. example.com).';

  // Each label: 1-63 chars, only letters/digits/hyphens, no leading/trailing hyphens
  const labels = domain.split('.');
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) return `Invalid label "${label}" in domain.`;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label) && label.length > 1) {
      return `Invalid characters in label "${label}".`;
    }
    if (!/^[a-z0-9]$/.test(label) && label.length === 1) {
      return `Invalid single-character label "${label}".`;
    }
  }

  return null; // valid
}

/* ==========================================================================
   DNS ENGINE
   ========================================================================== */

/**
 * Queries Google DNS-over-HTTPS API.
 * @param {string} name  — DNS name to query
 * @param {number} type  — DNS record type (use DNS_TYPE constants)
 * @returns {Promise<{Answer?: Array, Status: number, error?: string}>}
 */
async function queryDNS(name, type) {
  const url = new URL(CONFIG.API_ENDPOINTS.DOH);
  url.searchParams.set('name', name);
  url.searchParams.set('type', String(type));

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CONFIG.DNS_TIMEOUT_MS);

  try {
    const response = await fetch(url.toString(), {
      signal: controller.signal,
      headers: { Accept: 'application/dns-json' },
    });
    clearTimeout(timer);

    if (!response.ok) {
      return { Status: -1, error: `HTTP ${response.status}` };
    }

    const data = await response.json();
    // Validate the shape of the response
    if (typeof data !== 'object' || data === null || typeof data.Status === 'undefined') {
      return { Status: -1, error: 'Unexpected API response format.' };
    }
    return data;
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {
      return { Status: -1, error: 'DNS query timed out.' };
    }
    return { Status: -1, error: err.message || 'Network error.' };
  }
}

/**
 * Retrieves all records of one type for a domain.
 * Returns an array of data strings, or an empty array.
 * @param {string} name
 * @param {number} type
 * @returns {Promise<{records: string[], raw: object, error: string|null}>}
 */
async function fetchRecords(name, type) {
  const result = await queryDNS(name, type);

  if (result.error) {
    return { records: [], raw: result, error: result.error };
  }

  // Status 0 = no error, 3 = NXDOMAIN
  if (result.Status === 3) {
    return { records: [], raw: result, error: null }; // domain not found — not an error
  }
  if (result.Status !== 0) {
    return { records: [], raw: result, error: `DNS status code ${result.Status}` };
  }

  if (!Array.isArray(result.Answer)) {
    return { records: [], raw: result, error: null };
  }

  const records = result.Answer
    .filter(a => a.type === type)
    .map(a => {
      // TXT records returned with surrounding quotes — strip them
      return type === DNS_TYPE.TXT
        ? String(a.data).replace(/^"|"$/g, '')
        : String(a.data);
    });

  return { records, raw: result, error: null };
}

/**
 * Checks all standard DNS records for the domain.
 * @param {string} domain
 * @returns {Promise<object>}
 */
async function checkDNSRecords(domain) {
  const [aRes, aaaaRes, mxRes, nsRes, txtRes] = await Promise.allSettled([
    fetchRecords(domain, DNS_TYPE.A),
    fetchRecords(domain, DNS_TYPE.AAAA),
    fetchRecords(domain, DNS_TYPE.MX),
    fetchRecords(domain, DNS_TYPE.NS),
    fetchRecords(domain, DNS_TYPE.TXT),
  ]);

  return {
    a:    aRes.status    === 'fulfilled' ? aRes.value    : { records: [], error: 'Promise rejected' },
    aaaa: aaaaRes.status === 'fulfilled' ? aaaaRes.value : { records: [], error: 'Promise rejected' },
    mx:   mxRes.status   === 'fulfilled' ? mxRes.value   : { records: [], error: 'Promise rejected' },
    ns:   nsRes.status   === 'fulfilled' ? nsRes.value   : { records: [], error: 'Promise rejected' },
    txt:  txtRes.status  === 'fulfilled' ? txtRes.value  : { records: [], error: 'Promise rejected' },
  };
}

/**
 * Analyses SPF records from TXT results.
 * @param {string[]} txtRecords
 * @returns {{status: string, record: string|null, issues: string[], message: string}}
 */
function checkSPF(txtRecords) {
  const spfRecords = txtRecords.filter(r => r.startsWith('v=spf1'));

  if (spfRecords.length === 0) {
    return {
      status: STATUS.FAIL,
      record: null,
      issues: ['No SPF record found.'],
      message: 'No SPF record found in TXT records.',
    };
  }

  const issues = [];
  if (spfRecords.length > 1) {
    issues.push('Multiple SPF records found — only one is allowed. Email receivers will reject or ignore all SPF records.');
  }

  const spf = spfRecords[0];
  if (spf.includes('+all')) {
    issues.push('"~all" weak: "+all" means all hosts are authorised — effectively disables SPF protection.');
  }
  if (spf.includes('?all')) {
    issues.push('"?all" neutral: does not enforce SPF policy.');
  }
  if (!spf.includes('-all') && !spf.includes('~all') && !spf.includes('?all') && !spf.includes('+all')) {
    issues.push('SPF record does not end with an "all" mechanism.');
  }

  const tooPermissive = spf.includes('+all') || spf.includes('?all');
  const hasIssues = issues.length > 0;

  return {
    status: spfRecords.length > 1 || tooPermissive ? STATUS.FAIL : (hasIssues ? STATUS.WARN : STATUS.PASS),
    record: spf,
    issues,
    message: spfRecords.length > 1
      ? 'Multiple SPF records detected — this is a configuration error.'
      : (issues.length > 0 ? 'SPF found but has potential issues.' : 'Valid SPF record found.'),
  };
}

/**
 * Checks DMARC policy by querying _dmarc.<domain>.
 * @param {string} domain
 * @returns {Promise<{status: string, record: string|null, policy: string|null, issues: string[], message: string}>}
 */
async function checkDMARC(domain) {
  const { records, error } = await fetchRecords(`_dmarc.${domain}`, DNS_TYPE.TXT);

  if (error) {
    return { status: STATUS.UNKNOWN, record: null, policy: null, issues: [], message: `Query error: ${error}` };
  }

  const dmarcRecords = records.filter(r => r.startsWith('v=DMARC1'));

  if (dmarcRecords.length === 0) {
    return {
      status: STATUS.FAIL,
      record: null,
      policy: null,
      issues: ['No DMARC record found.'],
      message: 'No DMARC record found at _dmarc.' + domain,
    };
  }

  const dmarc = dmarcRecords[0];
  const policyMatch = dmarc.match(/p=([^;]+)/i);
  const policy = policyMatch ? policyMatch[1].toLowerCase().trim() : null;

  const issues = [];
  if (!policy || policy === 'none') {
    issues.push(`Policy is "${policy || 'none'}" — emails failing checks are not quarantined or rejected. Good for initial monitoring, but provides no enforcement.`);
  }

  const status = !policy || policy === 'none'
    ? STATUS.WARN
    : (policy === 'quarantine' ? STATUS.WARN : STATUS.PASS);

  return {
    status,
    record: dmarc,
    policy,
    issues,
    message: policy === 'reject'
      ? 'DMARC found with reject policy — maximum protection.'
      : (policy === 'quarantine'
        ? 'DMARC found with quarantine policy — moderate protection.'
        : `DMARC found with policy="${policy || 'none'}" — no enforcement.`),
  };
}

/**
 * Checks DKIM by testing one or more selectors.
 * @param {string} domain
 * @param {string|null} customSelector
 * @returns {Promise<{status: string, found: Array, tried: string[], message: string}>}
 */
async function checkDKIM(domain, customSelector) {
  const selectors = customSelector
    ? [customSelector.trim()]
    : CONFIG.DKIM_COMMON_SELECTORS;

  const results = await Promise.allSettled(
    selectors.map(sel => fetchRecords(`${sel}._domainkey.${domain}`, DNS_TYPE.TXT))
  );

  const found = [];
  const tried = [];

  results.forEach((res, i) => {
    const sel = selectors[i];
    tried.push(sel);
    if (res.status === 'fulfilled' && res.value.records.length > 0) {
      found.push({ selector: sel, records: res.value.records });
    }
  });

  if (found.length > 0) {
    return {
      status: STATUS.PASS,
      found,
      tried,
      message: `DKIM record found for selector(s): ${found.map(f => f.selector).join(', ')}.`,
    };
  }

  return {
    status: STATUS.WARN,
    found: [],
    tried,
    message: `No DKIM record found for tested selector(s): ${tried.join(', ')}. This does not confirm DKIM is absent — your provider may use a different selector.`,
  };
}

/* ==========================================================================
   HEADER ENGINE
   ========================================================================== */

/**
 * Parses raw HTTP headers pasted by the user.
 * Returns a Map<lowerCaseName, value>.
 * @param {string} raw
 * @returns {Map<string, string>}
 */
function parseHeaders(raw) {
  const map = new Map();
  if (!raw || typeof raw !== 'string') return map;

  const lines = raw.split(/\r?\n/);
  for (const line of lines) {
    // Skip the HTTP status line and blank lines
    if (!line.trim() || /^HTTP\//i.test(line)) continue;
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;
    const name = line.slice(0, colonIdx).trim().toLowerCase();
    const value = line.slice(colonIdx + 1).trim();
    if (name && value) {
      map.set(name, value);
    }
  }
  return map;
}

/**
 * Analyses Strict-Transport-Security header.
 * @param {string|undefined} value
 * @returns {{status: string, value: string|null, issues: string[]}}
 */
function analyzeHSTS(value) {
  if (!value) {
    return { status: STATUS.FAIL, value: null, issues: ['Header not present.'] };
  }

  const issues = [];
  const lower = value.toLowerCase();
  const maxAgeMatch = lower.match(/max-age=(\d+)/);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;

  if (!maxAgeMatch) {
    issues.push('max-age directive is missing.');
  } else if (maxAge < 31536000) {
    issues.push(`max-age=${maxAge} is less than 1 year (31536000 seconds). Consider increasing it.`);
  }

  if (!lower.includes('includesubdomains')) {
    issues.push('includeSubDomains is missing — subdomains are not covered by HSTS.');
  }

  return {
    status: issues.length === 0 ? STATUS.PASS : STATUS.WARN,
    value,
    issues,
  };
}

/**
 * Analyses Content-Security-Policy header.
 * @param {string|undefined} value
 * @returns {{status: string, value: string|null, issues: string[]}}
 */
function analyzeCSP(value) {
  if (!value) {
    return { status: STATUS.FAIL, value: null, issues: ['Header not present.'] };
  }

  const issues = [];
  const lower = value.toLowerCase();

  if (lower.includes("'unsafe-inline'") && lower.includes('script')) {
    issues.push("'unsafe-inline' in script context weakens CSP against XSS.");
  }
  if (lower.includes("'unsafe-eval'")) {
    issues.push("'unsafe-eval' allows JavaScript eval() — a significant XSS risk.");
  }
  if (lower.includes('*') && lower.includes('src')) {
    issues.push("Wildcard (*) in a src directive allows resources from any origin.");
  }
  if (!lower.includes('default-src') && !lower.includes('script-src')) {
    issues.push("No default-src or script-src directive found.");
  }

  return {
    status: issues.length === 0 ? STATUS.PASS : STATUS.WARN,
    value,
    issues,
  };
}

/**
 * Analyses X-Frame-Options header.
 * @param {string|undefined} value
 * @returns {{status: string, value: string|null, issues: string[]}}
 */
function analyzeXFrameOptions(value) {
  if (!value) {
    return { status: STATUS.FAIL, value: null, issues: ['Header not present.'] };
  }

  const upper = value.toUpperCase().trim();
  const issues = [];

  if (upper !== 'DENY' && upper !== 'SAMEORIGIN' && !upper.startsWith('ALLOW-FROM')) {
    issues.push(`Unrecognised value "${value}". Expected DENY or SAMEORIGIN.`);
  }
  if (upper.startsWith('ALLOW-FROM')) {
    issues.push('ALLOW-FROM is deprecated and not supported in modern browsers. Consider using CSP frame-ancestors instead.');
  }

  return {
    status: issues.length === 0 ? STATUS.PASS : STATUS.WARN,
    value,
    issues,
  };
}

/**
 * Analyses X-Content-Type-Options header.
 * @param {string|undefined} value
 * @returns {{status: string, value: string|null, issues: string[]}}
 */
function analyzeContentTypeOptions(value) {
  if (!value) {
    return { status: STATUS.FAIL, value: null, issues: ['Header not present.'] };
  }

  const issues = [];
  if (value.toLowerCase().trim() !== 'nosniff') {
    issues.push(`Value "${value}" is not "nosniff". Only "nosniff" activates MIME-type protection.`);
  }

  return {
    status: issues.length === 0 ? STATUS.PASS : STATUS.WARN,
    value,
    issues,
  };
}

/**
 * Analyses Referrer-Policy header.
 * @param {string|undefined} value
 * @returns {{status: string, value: string|null, issues: string[]}}
 */
function analyzeReferrerPolicy(value) {
  if (!value) {
    return { status: STATUS.FAIL, value: null, issues: ['Header not present.'] };
  }

  const strong = [
    'no-referrer',
    'no-referrer-when-downgrade',
    'strict-origin',
    'strict-origin-when-cross-origin',
    'same-origin',
  ];
  const weak = ['unsafe-url', 'origin', 'origin-when-cross-origin'];
  const lower = value.toLowerCase().trim();
  const issues = [];

  if (weak.includes(lower)) {
    issues.push(`"${value}" may expose URL paths in the Referer header to third parties.`);
  } else if (!strong.includes(lower)) {
    issues.push(`Unrecognised Referrer-Policy value "${value}".`);
  }

  return {
    status: issues.length === 0 ? STATUS.PASS : STATUS.WARN,
    value,
    issues,
  };
}

/**
 * Analyses Permissions-Policy header.
 * @param {string|undefined} value
 * @returns {{status: string, value: string|null, issues: string[]}}
 */
function analyzePermissionsPolicy(value) {
  if (!value) {
    return { status: STATUS.FAIL, value: null, issues: ['Header not present.'] };
  }
  // If present, it's a good sign — do basic presence check
  return { status: STATUS.PASS, value, issues: [] };
}

/* ==========================================================================
   HTTPS ENGINE
   ========================================================================== */

/**
 * Attempts to determine HTTPS availability via browser fetch.
 * Due to CORS, this will often be blocked for cross-origin responses,
 * but a successful opaque response confirms connectivity.
 * @param {string} domain
 * @returns {Promise<{httpsAvailable: string, httpRedirect: string, note: string}>}
 */
async function checkHTTPSAvailability(domain) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CONFIG.FETCH_TIMEOUT_MS);

  let httpsAvailable = STATUS.UNKNOWN;
  let httpRedirect   = STATUS.UNKNOWN;
  let note = '';

  try {
    // mode:no-cors means we won't get headers but won't get a CORS error either
    const res = await fetch(`https://${domain}`, {
      method: 'HEAD',
      mode: 'no-cors',
      signal: controller.signal,
      redirect: 'follow',
    });
    clearTimeout(timer);

    // opaque response (type==='opaque') means the request succeeded
    if (res.type === 'opaque' || res.ok || res.status === 0) {
      httpsAvailable = STATUS.PASS;
      note = 'HTTPS connection succeeded (opaque response — CORS prevented header inspection).';
    } else {
      httpsAvailable = STATUS.WARN;
      note = `Unexpected response status: ${res.status}`;
    }
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {
      note = 'HTTPS connection attempt timed out.';
      httpsAvailable = STATUS.WARN;
    } else {
      // Network error or DNS failure
      note = `HTTPS connection failed: ${err.message || 'Network error.'}`;
      httpsAvailable = STATUS.FAIL;
    }
  }

  // We cannot reliably detect HTTP→HTTPS redirect from a static frontend
  // without server-side assistance
  httpRedirect = STATUS.UNKNOWN;

  return { httpsAvailable, httpRedirect, note };
}

/* ==========================================================================
   RISK ENGINE
   ========================================================================== */

/**
 * Calculates the security risk score from a normalised results map.
 * UNKNOWN checks are excluded from the denominator.
 * @param {Object} checks  — { checkId: STATUS.* }
 * @returns {{ score: number, applicable: number, passed: number, warnings: number, failed: number, unknown: number }}
 */
function calculateRiskScore(checks) {
  const weights = CONFIG.SECURITY_WEIGHTS;
  let totalWeight = 0;
  let earnedWeight = 0;
  let passed = 0, warnings = 0, failed = 0, unknown = 0;

  for (const [id, status] of Object.entries(checks)) {
    const w = weights[id];
    if (w === undefined) continue; // check not in scoring table

    if (status === STATUS.UNKNOWN || status === STATUS.INFO) {
      unknown++;
      continue; // excluded from denominator
    }

    totalWeight += w;

    if (status === STATUS.PASS) {
      earnedWeight += w;
      passed++;
    } else if (status === STATUS.WARN) {
      earnedWeight += w * 0.5; // partial credit for warnings
      warnings++;
    } else {
      failed++;
    }
  }

  const score = totalWeight === 0 ? 0 : Math.round((earnedWeight / totalWeight) * 100);

  return {
    score,
    applicable: passed + warnings + failed,
    passed,
    warnings,
    failed,
    unknown,
  };
}

/**
 * Returns risk level and colour class based on score.
 * @param {number} score
 * @returns {{ level: string, colorClass: string, arcClass: string }}
 */
function determineRiskLevel(score) {
  if (score >= 90) return { level: 'Low Risk',      colorClass: 'text-emerald-400', arcClass: 'score-low' };
  if (score >= 70) return { level: 'Medium Risk',   colorClass: 'text-amber-400',   arcClass: 'score-medium' };
  if (score >= 40) return { level: 'High Risk',     colorClass: 'text-orange-400',  arcClass: 'score-high' };
  return              { level: 'Critical Risk',  colorClass: 'text-red-400',     arcClass: 'score-critical' };
}

/* ==========================================================================
   REPORT ENGINE — findings data
   ========================================================================== */

/**
 * Returns all educational finding definitions keyed by check ID.
 * Content in English with simplified explanations.
 */
function getFindings() {
  return {
    https_availability: {
      label: 'HTTPS Availability',
      what: 'Whether the website is accessible over an encrypted HTTPS connection.',
      why: 'HTTPS encrypts data between the visitor and the server, protecting passwords, personal data, and session cookies from eavesdroppers.',
      risk: 'Without HTTPS, attackers on the same network (e.g., public Wi-Fi) can intercept and read all data transmitted between users and your site.',
      fix: 'Obtain an SSL/TLS certificate (free from Let\'s Encrypt) and configure your web server to serve content over HTTPS.',
      config: '# Redirect all HTTP to HTTPS (Apache)\nRewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]',
    },
    hsts: {
      label: 'HTTP Strict Transport Security (HSTS)',
      what: 'The Strict-Transport-Security header instructs browsers to only connect to your site over HTTPS for a specified duration.',
      why: 'HSTS prevents protocol downgrade attacks and cookie hijacking by ensuring browsers never send requests over insecure HTTP, even if the user types http:// manually.',
      risk: 'Without HSTS, attackers can intercept the first HTTP request and redirect users to a fake site (SSL stripping attack).',
      fix: 'Add the Strict-Transport-Security header to your server\'s HTTPS response. Start with a short max-age, then increase after testing.',
      config: 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
    },
    csp: {
      label: 'Content Security Policy (CSP)',
      what: 'The Content-Security-Policy header defines which sources of content (scripts, styles, images) are allowed to load on your page.',
      why: 'CSP is the primary defense against Cross-Site Scripting (XSS) attacks, which are among the most common web vulnerabilities.',
      risk: 'Without CSP, an attacker who can inject HTML or JavaScript into your page can steal session cookies, redirect users, or perform actions on their behalf.',
      fix: 'Add a Content-Security-Policy header. Start with a report-only policy to identify issues before enforcing.',
      config: "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
    },
    x_frame_options: {
      label: 'X-Frame-Options',
      what: 'The X-Frame-Options header controls whether your page can be embedded in an <iframe> on another site.',
      why: 'Prevents clickjacking attacks where an attacker overlays an invisible iframe of your site on top of a malicious page, tricking users into clicking on hidden elements.',
      risk: 'Without this header, your login form or payment page could be embedded in a malicious page and used to steal credentials or trigger unauthorised actions.',
      fix: 'Add X-Frame-Options: SAMEORIGIN to allow framing only from your own origin, or DENY to block all framing.',
      config: 'X-Frame-Options: SAMEORIGIN',
    },
    x_content_type_options: {
      label: 'X-Content-Type-Options',
      what: 'The X-Content-Type-Options: nosniff header prevents browsers from MIME-type sniffing — guessing the content type of a response.',
      why: 'Some older browsers would execute JavaScript even if served with a non-script MIME type (e.g., text/plain), enabling attacks via uploaded files.',
      risk: 'Without this header, an attacker who can upload files to your server might be able to execute malicious scripts by exploiting MIME sniffing.',
      fix: 'Add the X-Content-Type-Options header with the value nosniff.',
      config: 'X-Content-Type-Options: nosniff',
    },
    referrer_policy: {
      label: 'Referrer-Policy',
      what: 'The Referrer-Policy header controls how much referrer information the browser sends with requests originating from your page.',
      why: 'Without a strict policy, your page URLs (which may contain session tokens, search terms, or sensitive paths) are sent to external servers in the Referer header.',
      risk: 'Sensitive URLs leaked via the Referer header can expose private data to analytics providers, CDNs, or attackers who compromise third-party resources.',
      fix: 'Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer for the best balance of privacy and functionality.',
      config: 'Referrer-Policy: strict-origin-when-cross-origin',
    },
    permissions_policy: {
      label: 'Permissions-Policy',
      what: 'The Permissions-Policy header (formerly Feature-Policy) controls which browser features (camera, microphone, geolocation, etc.) your page and embedded iframes can use.',
      why: 'Restricting unnecessary browser APIs reduces your attack surface and prevents malicious third-party scripts from silently accessing sensitive device features.',
      risk: 'Without this header, malicious ad scripts or third-party iframes embedded on your site could potentially access the user\'s camera, microphone, or location.',
      fix: 'Add a Permissions-Policy header listing only the features your site actually needs.',
      config: 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()',
    },
    spf: {
      label: 'Sender Policy Framework (SPF)',
      what: 'An SPF record is a DNS TXT record that lists which mail servers are authorised to send email on behalf of your domain.',
      why: 'SPF allows receiving mail servers to verify that incoming mail from your domain comes from an authorised server, reducing email spoofing and phishing.',
      risk: 'Without SPF, anyone can send email that appears to come from your domain, enabling phishing attacks and damaging your domain\'s reputation.',
      fix: 'Create a TXT record for your domain specifying your authorised sending IP addresses or services.',
      config: 'v=spf1 include:_spf.google.com ~all',
    },
    dmarc: {
      label: 'DMARC Policy',
      what: 'DMARC (Domain-based Message Authentication, Reporting, and Conformance) builds on SPF and DKIM to specify how receiving servers should handle unauthenticated email.',
      why: 'DMARC provides a policy for email receivers and delivers aggregate reports so you can see who is sending email from your domain.',
      risk: 'Without DMARC, even if you have SPF and DKIM, there is no instruction to receivers about what to do with emails that fail authentication — allowing spoofed email through.',
      fix: 'Create a DMARC TXT record at _dmarc.yourdomain.com. Start with p=none to monitor, then graduate to quarantine or reject.',
      config: 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com; ruf=mailto:dmarc-failures@yourdomain.com; fo=1',
    },
    dkim: {
      label: 'DKIM (DomainKeys Identified Mail)',
      what: 'DKIM adds a cryptographic signature to outgoing emails, allowing receiving servers to verify that the email content was not modified in transit.',
      why: 'DKIM proves email integrity and authenticity, complementing SPF (which only authenticates the sending server).',
      risk: 'Without DKIM, email content can be modified in transit by attackers (man-in-the-middle), and your domain is more susceptible to spoofing.',
      fix: 'Configure DKIM in your email sending platform (e.g., Google Workspace, Microsoft 365) and publish the public key as a DNS TXT record at <selector>._domainkey.yourdomain.com.',
      config: '# Example DKIM DNS record (your key will be different)\nv=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN...',
    },
  };
}

/* ==========================================================================
   UI ENGINE
   ========================================================================== */

/** Cached element references */
const UI = {
  get domainInput()     { return document.getElementById('domain-input'); },
  get dkimSelector()    { return document.getElementById('dkim-selector'); },
  get headersInput()    { return document.getElementById('headers-input'); },
  get domainError()     { return document.getElementById('domain-error'); },
  get scanBtnMain()     { return document.getElementById('scan-btn-main'); },
  get scanBtn()         { return document.getElementById('scan-btn'); },
  get demoBtn()         { return document.getElementById('demo-btn'); },
  get resetBtn()        { return document.getElementById('reset-btn'); },
  get progressSection() { return document.getElementById('progress-section'); },
  get progressLabel()   { return document.getElementById('progress-label'); },
  get progressPct()     { return document.getElementById('progress-pct'); },
  get progressBar()     { return document.getElementById('progress-bar'); },
  get progressBarContainer() { return document.getElementById('progress-bar-container'); },
  get progressSteps()   { return document.getElementById('progress-steps'); },
  get resultsSection()  { return document.getElementById('results'); },
  get demoBanner()      { return document.getElementById('demo-banner'); },
  get scoreValue()      { return document.getElementById('score-value'); },
  get scoreLabel()      { return document.getElementById('score-label'); },
  get riskLevel()       { return document.getElementById('risk-level'); },
  get scoreArc()        { return document.getElementById('score-arc'); },
  get countPass()       { return document.getElementById('count-pass'); },
  get countWarn()       { return document.getElementById('count-warn'); },
  get countFail()       { return document.getElementById('count-fail'); },
  get countUnknown()    { return document.getElementById('count-unknown'); },
  get scoreExplanation(){ return document.getElementById('score-explanation'); },
  get checksGrid()      { return document.getElementById('checks-grid'); },
  get findingsAccordion(){ return document.getElementById('findings-accordion'); },
  get dnsRecordsContainer(){ return document.getElementById('dns-records-container'); },
  get tlsInfo()         { return document.getElementById('tls-info'); },
};

/** Progress step tracking */
let progressStepList = [];

function renderProgress(pct, label) {
  UI.progressLabel.textContent = label;
  UI.progressPct.textContent   = `${pct}%`;
  UI.progressBar.style.width   = `${pct}%`;
  UI.progressBarContainer.setAttribute('aria-valuenow', String(pct));
}

function addProgressStep(text, state = 'active') {
  progressStepList.push({ text, state });
  renderProgressSteps();
}

function completeProgressStep(text) {
  // Use a manual reverse search for broad browser compatibility (avoids Array.findLast)
  for (let i = progressStepList.length - 1; i >= 0; i--) {
    const s = progressStepList[i];
    if (s.text === text && s.state === 'active') {
      s.state = 'done';
      break;
    }
  }
  renderProgressSteps();
}

function renderProgressSteps() {
  UI.progressSteps.innerHTML = '';
  for (const step of progressStepList) {
    const li = document.createElement('li');
    li.className = `progress-step ${step.state}`;
    const icon = step.state === 'done'    ? '✓'
               : step.state === 'active'  ? '›'
               : '○';
    const span = document.createElement('span');
    span.textContent = `${icon} ${step.text}`;
    li.appendChild(span);
    UI.progressSteps.appendChild(li);
  }
}

function showProgress() {
  UI.progressSection.classList.remove('hidden');
  progressStepList = [];
}

function hideProgress() {
  UI.progressSection.classList.add('hidden');
}

function showResults(isDemo) {
  UI.resultsSection.classList.remove('hidden');
  if (isDemo) {
    UI.demoBanner.classList.remove('hidden');
  } else {
    UI.demoBanner.classList.add('hidden');
  }
}

/** Shows the error message below the domain input */
function showDomainError(msg) {
  UI.domainError.textContent = msg;
  UI.domainError.classList.remove('hidden');
  UI.domainInput.setAttribute('aria-invalid', 'true');
}

function clearDomainError() {
  UI.domainError.textContent = '';
  UI.domainError.classList.add('hidden');
  UI.domainInput.removeAttribute('aria-invalid');
}

/**
 * Resets the entire application to its initial state.
 */
function resetApplication() {
  UI.domainInput.value    = '';
  UI.dkimSelector.value   = '';
  UI.headersInput.value   = '';
  clearDomainError();
  hideProgress();
  UI.resultsSection.classList.add('hidden');
  UI.demoBanner.classList.add('hidden');
  UI.resetBtn.classList.add('hidden');
  UI.scanBtnMain.disabled = false;
  UI.demoBtn.disabled     = false;

  // Clear score
  UI.scoreValue.textContent = '—';
  UI.scoreLabel.textContent = 'Not scanned';
  UI.riskLevel.textContent  = '—';
  UI.scoreArc.style.strokeDashoffset = '314';
  UI.scoreArc.className.baseVal = '';

  ['countPass','countWarn','countFail','countUnknown'].forEach(id => {
    UI[id].textContent = '—';
  });
  UI.scoreExplanation.textContent = '';
  UI.checksGrid.innerHTML          = '';
  UI.findingsAccordion.innerHTML   = '';
  UI.dnsRecordsContainer.innerHTML = '';
  UI.tlsInfo.innerHTML             = '';
}

/** Renders the circular score gauge */
function renderScore(scoreData) {
  const { score, passed, warnings, failed, unknown, applicable } = scoreData;
  const { level, colorClass, arcClass } = determineRiskLevel(score);

  UI.scoreValue.textContent = String(score);
  UI.scoreLabel.textContent = level;
  UI.riskLevel.textContent  = level;
  UI.riskLevel.className    = `text-sm font-semibold px-3 py-1 rounded-full border border-slate-700 ${colorClass}`;

  // Animate arc: circumference = 2π×50 ≈ 314.16
  const circumference = 314.16;
  const offset = circumference - (score / 100) * circumference;
  UI.scoreArc.style.strokeDashoffset = String(offset);
  UI.scoreArc.className.baseVal = arcClass;

  UI.countPass.textContent    = String(passed);
  UI.countWarn.textContent    = String(warnings);
  UI.countFail.textContent    = String(failed);
  UI.countUnknown.textContent = String(unknown);

  UI.scoreExplanation.textContent =
    `Score calculated from ${applicable} verifiable check(s). ` +
    `${unknown} check(s) excluded from scoring (marked UNKNOWN or unverifiable). ` +
    `Warnings receive 50% credit. Final score: ${score}/100.`;
}

/** Renders the security checks grid */
function renderChecksGrid(checksMap) {
  UI.checksGrid.innerHTML = '';
  const findings = getFindings();

  for (const [id, status] of Object.entries(checksMap)) {
    const info = findings[id];
    if (!info) continue;

    const card = document.createElement('div');
    card.className = `check-card status-${status}`;

    const top = document.createElement('div');
    top.className = 'flex items-center justify-between gap-2';

    const label = document.createElement('span');
    label.className = 'text-sm font-medium text-slate-200';
    label.textContent = info.label;

    const badge = document.createElement('span');
    badge.className = `badge badge-${status}`;
    badge.textContent = status.toUpperCase();

    top.appendChild(label);
    top.appendChild(badge);
    card.appendChild(top);
    UI.checksGrid.appendChild(card);
  }
}

/** Creates a safe text node — never uses innerHTML for user data */
function safeText(text) {
  return document.createTextNode(String(text));
}

/** Creates a code block element */
function createCodeBlock(code) {
  const pre = document.createElement('pre');
  pre.className = 'code-block mt-2';
  pre.appendChild(safeText(code));
  return pre;
}

/** Creates a copy button that copies the given text */
function createCopyButton(textToCopy) {
  const btn = document.createElement('button');
  btn.className = 'copy-btn';
  btn.setAttribute('type', 'button');
  btn.setAttribute('aria-label', 'Copy configuration to clipboard');
  // Security note: innerHTML here is intentional and safe — the SVG is a
  // 100% hardcoded static string with no user-controlled content whatsoever.
  btn.innerHTML = `<svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg> Copy`;
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(textToCopy);
      btn.textContent = '✓ Copied';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.innerHTML = `<svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg> Copy`;
        btn.classList.remove('copied');
      }, 2000);
    } catch {
      btn.textContent = 'Copy failed';
    }
  });
  return btn;
}

/**
 * Renders the detailed findings accordion.
 * @param {Object} checksMap   — { checkId: STATUS.* }
 * @param {Object} detailsMap  — { checkId: { value, issues, message, … } }
 */
function renderFindings(checksMap, detailsMap) {
  UI.findingsAccordion.innerHTML = '';
  const findings = getFindings();

  for (const [id, status] of Object.entries(checksMap)) {
    const info    = findings[id];
    const details = detailsMap[id] || {};
    if (!info) continue;

    const item = document.createElement('div');
    item.className = `accordion-item status-${status}`;

    // Trigger
    const trigger = document.createElement('button');
    trigger.className = 'accordion-trigger';
    trigger.setAttribute('type', 'button');
    trigger.setAttribute('aria-expanded', 'false');

    const left = document.createElement('div');
    left.className = 'flex items-center gap-3 flex-1 min-w-0';

    const badge = document.createElement('span');
    badge.className = `badge badge-${status} flex-shrink-0`;
    badge.textContent = status.toUpperCase();

    const lbl = document.createElement('span');
    lbl.className = 'font-medium text-sm truncate';
    lbl.textContent = info.label;

    left.appendChild(badge);
    left.appendChild(lbl);

    const chevron = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    chevron.setAttribute('class', 'accordion-chevron');
    chevron.setAttribute('fill', 'none');
    chevron.setAttribute('stroke', 'currentColor');
    chevron.setAttribute('viewBox', '0 0 24 24');
    chevron.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('stroke-linecap', 'round');
    path.setAttribute('stroke-linejoin', 'round');
    path.setAttribute('stroke-width', '2');
    path.setAttribute('d', 'M19 9l-7 7-7-7');
    chevron.appendChild(path);

    trigger.appendChild(left);
    trigger.appendChild(chevron);

    // Content
    const contentWrapper = document.createElement('div');
    contentWrapper.className = 'accordion-content';

    const body = document.createElement('div');
    body.className = 'accordion-body space-y-4';

    // Current value
    if (details.value || details.record || details.message) {
      const valueSection = document.createElement('div');
      const vTitle = document.createElement('p');
      vTitle.className = 'finding-section-title';
      vTitle.textContent = 'What Was Found?';
      valueSection.appendChild(vTitle);

      const vText = document.createElement('p');
      vText.className = 'text-sm text-slate-300';
      vText.textContent = details.message || (details.value ? `Value: ${details.value}` : '—');
      valueSection.appendChild(vText);

      if (details.value || details.record) {
        const cb = createCodeBlock(details.value || details.record);
        valueSection.appendChild(cb);
      }

      body.appendChild(valueSection);
    }

    // Issues list
    if (details.issues && details.issues.length > 0) {
      const issueSection = document.createElement('div');
      const iTitle = document.createElement('p');
      iTitle.className = 'finding-section-title';
      iTitle.textContent = 'Issues Detected';
      issueSection.appendChild(iTitle);
      const ul = document.createElement('ul');
      ul.className = 'list-disc list-inside space-y-1';
      details.issues.forEach(issue => {
        const li = document.createElement('li');
        li.className = 'text-sm text-amber-300';
        li.textContent = issue;
        ul.appendChild(li);
      });
      issueSection.appendChild(ul);
      body.appendChild(issueSection);
    }

    // Educational sections
    const sections = [
      { key: 'why',  title: 'Why Does It Matter?' },
      { key: 'risk', title: 'What Is the Potential Risk?' },
      { key: 'fix',  title: 'How Can It Be Fixed?' },
    ];
    for (const { key, title } of sections) {
      if (!info[key]) continue;
      const sec = document.createElement('div');
      const t = document.createElement('p');
      t.className = 'finding-section-title';
      t.textContent = title;
      const p = document.createElement('p');
      p.className = 'text-sm text-slate-400';
      p.textContent = info[key];
      sec.appendChild(t);
      sec.appendChild(p);
      body.appendChild(sec);
    }

    // Config example
    if (info.config) {
      const configSection = document.createElement('div');
      const cTitle = document.createElement('p');
      cTitle.className = 'finding-section-title';
      cTitle.textContent = 'Example Configuration';
      configSection.appendChild(cTitle);

      const codeWrap = document.createElement('div');
      codeWrap.className = 'relative';
      const cb = createCodeBlock(info.config);
      const copyBtn = createCopyButton(info.config);
      copyBtn.style.position = 'absolute';
      copyBtn.style.top = '0.5rem';
      copyBtn.style.right = '0.5rem';

      codeWrap.appendChild(cb);
      codeWrap.appendChild(copyBtn);
      configSection.appendChild(codeWrap);

      const note = document.createElement('p');
      note.className = 'text-xs text-slate-500 mt-2';
      note.textContent = '⚠ Always test configuration changes in a staging environment before applying to production.';
      configSection.appendChild(note);

      body.appendChild(configSection);
    }

    // Data source & confidence
    if (details.source || details.confidence) {
      const srcSection = document.createElement('div');
      srcSection.className = 'flex flex-wrap gap-2 pt-2 border-t border-slate-700';
      if (details.source) {
        const st = document.createElement('span');
        st.className = 'confidence-tag';
        st.textContent = `Source: ${details.source}`;
        srcSection.appendChild(st);
      }
      if (details.confidence) {
        const ct = document.createElement('span');
        ct.className = 'confidence-tag';
        ct.textContent = `Confidence: ${details.confidence}`;
        srcSection.appendChild(ct);
      }
      body.appendChild(srcSection);
    }

    contentWrapper.appendChild(body);
    item.appendChild(trigger);
    item.appendChild(contentWrapper);

    // Toggle accordion
    trigger.addEventListener('click', () => {
      const isOpen = item.classList.contains('open');
      item.classList.toggle('open', !isOpen);
      trigger.setAttribute('aria-expanded', String(!isOpen));
    });

    UI.findingsAccordion.appendChild(item);
  }
}

/** Renders DNS records section */
function renderDNSRecords(dnsData) {
  UI.dnsRecordsContainer.innerHTML = '';

  const groups = [
    { key: 'a',    label: 'A Records (IPv4)',   type: 'A' },
    { key: 'aaaa', label: 'AAAA Records (IPv6)', type: 'AAAA' },
    { key: 'mx',   label: 'MX Records (Mail)',   type: 'MX' },
    { key: 'ns',   label: 'NS Records (Nameservers)', type: 'NS' },
    { key: 'txt',  label: 'TXT Records',         type: 'TXT' },
  ];

  for (const { key, label, type } of groups) {
    const data = dnsData[key];
    if (!data) continue;

    const wrap = document.createElement('div');
    wrap.className = 'dns-record-group';

    const header = document.createElement('div');
    header.className = 'dns-record-header';

    const lbl = document.createElement('span');
    lbl.className = 'text-sm font-medium text-slate-300';
    lbl.textContent = label;

    const badge = document.createElement('span');
    badge.className = `badge ${data.records.length > 0 ? 'badge-pass' : (data.error ? 'badge-unknown' : 'badge-info')}`;
    badge.textContent = data.error ? 'ERROR' : (data.records.length > 0 ? `${data.records.length} FOUND` : 'NOT FOUND');

    header.appendChild(lbl);
    header.appendChild(badge);

    const recordBody = document.createElement('div');

    if (data.error) {
      recordBody.className = 'dns-record-body empty';
      recordBody.textContent = `Query error: ${data.error}`;
    } else if (data.records.length === 0) {
      recordBody.className = 'dns-record-body empty';
      recordBody.textContent = `No ${type} records found.`;
    } else {
      recordBody.className = 'dns-record-body';
      recordBody.textContent = data.records.join('\n');
    }

    wrap.appendChild(header);
    wrap.appendChild(recordBody);
    UI.dnsRecordsContainer.appendChild(wrap);
  }
}

/** Renders HTTPS/TLS info section */
function renderTLSInfo(httpsResult) {
  UI.tlsInfo.innerHTML = '';

  const rows = [
    {
      label: 'HTTPS Availability',
      status: httpsResult.httpsAvailable,
      note: httpsResult.note || 'HTTPS connection check attempted.',
      available: true,
    },
    {
      label: 'HTTP → HTTPS Redirect',
      status: STATUS.UNKNOWN,
      note: 'Cannot be reliably verified from a browser-only application without server-side access.',
      available: false,
    },
    {
      label: 'TLS Certificate Chain',
      status: STATUS.UNKNOWN,
      note: 'Not Available in Browser-Only Mode — requires server-side TLS inspection.',
      available: false,
    },
    {
      label: 'Cipher Suite Negotiation',
      status: STATUS.UNKNOWN,
      note: 'Not Available in Browser-Only Mode — requires server-side TLS inspection (e.g., OpenSSL, testssl.sh).',
      available: false,
    },
    {
      label: 'Certificate Expiry / Revocation',
      status: STATUS.UNKNOWN,
      note: 'Not Available in Browser-Only Mode — check manually at https://www.ssllabs.com/ssltest/',
      available: false,
    },
  ];

  for (const row of rows) {
    const item = document.createElement('div');
    item.className = 'tls-item';

    const left = document.createElement('div');
    left.className = 'flex-1';

    const lbl = document.createElement('p');
    lbl.className = 'text-sm font-medium text-slate-200';
    lbl.textContent = row.label;

    const noteEl = document.createElement('p');
    noteEl.className = 'text-xs text-slate-400 mt-0.5';
    noteEl.textContent = row.note;

    left.appendChild(lbl);
    left.appendChild(noteEl);

    const badge = document.createElement('span');
    badge.className = `badge badge-${row.status} flex-shrink-0`;
    badge.textContent = row.available
      ? row.status.toUpperCase()
      : 'N/A';

    item.appendChild(left);
    item.appendChild(badge);
    UI.tlsInfo.appendChild(item);
  }
}

/* ==========================================================================
   ORCHESTRATOR — Full Scan
   ========================================================================== */

/**
 * Runs the full security scan for a domain.
 * @param {string} domain
 * @param {string|null} dkimSelector
 * @param {string} rawHeaders
 */
async function runScan(domain, dkimSelector, rawHeaders) {
  UI.scanBtnMain.disabled = true;
  UI.demoBtn.disabled     = true;
  UI.resetBtn.classList.remove('hidden');
  showProgress();
  renderProgress(0, 'Starting scan…');

  try {
    // --- Phase 1: DNS Records ---
    addProgressStep('Querying DNS records…');
    renderProgress(10, 'Querying DNS records…');
    const dnsData = await checkDNSRecords(domain);
    completeProgressStep('Querying DNS records…');

    // --- Phase 2: Email Auth ---
    addProgressStep('Checking SPF…');
    renderProgress(30, 'Checking email authentication…');
    const spfResult   = checkSPF(dnsData.txt.records);
    completeProgressStep('Checking SPF…');

    addProgressStep('Checking DMARC…');
    renderProgress(45, 'Checking DMARC…');
    const dmarcResult = await checkDMARC(domain);
    completeProgressStep('Checking DMARC…');

    addProgressStep('Checking DKIM…');
    renderProgress(55, 'Checking DKIM…');
    const dkimResult  = await checkDKIM(domain, dkimSelector);
    completeProgressStep('Checking DKIM…');

    // --- Phase 3: HTTPS ---
    addProgressStep('Testing HTTPS availability…');
    renderProgress(70, 'Testing HTTPS…');
    const httpsResult = await checkHTTPSAvailability(domain);
    completeProgressStep('Testing HTTPS availability…');

    // --- Phase 4: Headers ---
    addProgressStep('Analysing security headers…');
    renderProgress(85, 'Analysing security headers…');
    const headerMap = parseHeaders(rawHeaders);
    const hasUserHeaders = headerMap.size > 0;

    const hstsAnalysis  = analyzeHSTS(headerMap.get('strict-transport-security'));
    const cspAnalysis   = analyzeCSP(headerMap.get('content-security-policy'));
    const xfoAnalysis   = analyzeXFrameOptions(headerMap.get('x-frame-options'));
    const xctoAnalysis  = analyzeContentTypeOptions(headerMap.get('x-content-type-options'));
    const rpAnalysis    = analyzeReferrerPolicy(headerMap.get('referrer-policy'));
    const ppAnalysis    = analyzePermissionsPolicy(headerMap.get('permissions-policy'));

    // If no user headers provided and browser cannot fetch headers,
    // mark header checks as UNKNOWN
    const headerSource = hasUserHeaders ? 'User-provided headers' : 'Unable to Verify';
    const headerConf   = hasUserHeaders ? 'High (user-provided)' : 'None (browser CORS restriction)';

    // If no user headers, we cannot confirm header presence/absence
    const effectiveHeaderStatus = (analysis) => {
      if (hasUserHeaders) return analysis.status;
      return STATUS.UNKNOWN;
    };

    completeProgressStep('Analysing security headers…');
    renderProgress(95, 'Calculating score…');

    // --- Assemble checks map ---
    const checksMap = {
      https_availability:     httpsResult.httpsAvailable,
      hsts:                   effectiveHeaderStatus(hstsAnalysis),
      csp:                    effectiveHeaderStatus(cspAnalysis),
      x_frame_options:        effectiveHeaderStatus(xfoAnalysis),
      x_content_type_options: effectiveHeaderStatus(xctoAnalysis),
      referrer_policy:        effectiveHeaderStatus(rpAnalysis),
      permissions_policy:     effectiveHeaderStatus(ppAnalysis),
      spf:                    spfResult.status,
      dmarc:                  dmarcResult.status,
      dkim:                   dkimResult.status,
    };

    // --- Details map for findings ---
    const detailsMap = {
      https_availability: {
        status: httpsResult.httpsAvailable,
        message: httpsResult.note,
        source: 'Browser Fetch API',
        confidence: 'Medium (opaque response — CORS limited)',
      },
      hsts: {
        ...hstsAnalysis,
        message: hasUserHeaders
          ? (hstsAnalysis.value ? `Found: ${hstsAnalysis.value}` : 'Header not present in provided headers.')
          : 'Unable to Verify: Browser security restrictions prevented header inspection. Paste HTTP headers to enable this check.',
        source: headerSource,
        confidence: headerConf,
      },
      csp: {
        ...cspAnalysis,
        message: hasUserHeaders
          ? (cspAnalysis.value ? `Found: ${cspAnalysis.value}` : 'Content-Security-Policy header not present.')
          : 'Unable to Verify: Paste HTTP response headers to enable this check.',
        source: headerSource,
        confidence: headerConf,
      },
      x_frame_options: {
        ...xfoAnalysis,
        message: hasUserHeaders
          ? (xfoAnalysis.value ? `Found: ${xfoAnalysis.value}` : 'X-Frame-Options header not present.')
          : 'Unable to Verify: Paste HTTP response headers to enable this check.',
        source: headerSource,
        confidence: headerConf,
      },
      x_content_type_options: {
        ...xctoAnalysis,
        message: hasUserHeaders
          ? (xctoAnalysis.value ? `Found: ${xctoAnalysis.value}` : 'X-Content-Type-Options header not present.')
          : 'Unable to Verify: Paste HTTP response headers to enable this check.',
        source: headerSource,
        confidence: headerConf,
      },
      referrer_policy: {
        ...rpAnalysis,
        message: hasUserHeaders
          ? (rpAnalysis.value ? `Found: ${rpAnalysis.value}` : 'Referrer-Policy header not present.')
          : 'Unable to Verify: Paste HTTP response headers to enable this check.',
        source: headerSource,
        confidence: headerConf,
      },
      permissions_policy: {
        ...ppAnalysis,
        message: hasUserHeaders
          ? (ppAnalysis.value ? `Found: ${ppAnalysis.value}` : 'Permissions-Policy header not present.')
          : 'Unable to Verify: Paste HTTP response headers to enable this check.',
        source: headerSource,
        confidence: headerConf,
      },
      spf: {
        ...spfResult,
        source: 'Google DNS-over-HTTPS',
        confidence: spfResult.status === STATUS.UNKNOWN ? 'Low' : 'High (live DNS)',
      },
      dmarc: {
        ...dmarcResult,
        source: 'Google DNS-over-HTTPS',
        confidence: dmarcResult.status === STATUS.UNKNOWN ? 'Low' : 'High (live DNS)',
      },
      dkim: {
        message: dkimResult.message,
        value: dkimResult.found.length > 0
          ? dkimResult.found.map(f => `${f.selector}._domainkey.${domain}\n${f.records.join('\n')}`).join('\n\n')
          : null,
        issues: [],
        source: 'Google DNS-over-HTTPS',
        confidence: 'Medium (common selectors only — your provider may use a different selector)',
      },
    };

    // --- Score ---
    const scoreData = calculateRiskScore(checksMap);
    renderProgress(100, 'Scan complete!');
    addProgressStep('Scan complete!');

    setTimeout(() => {
      hideProgress();
      showResults(false);
      renderScore(scoreData);
      renderChecksGrid(checksMap);
      renderFindings(checksMap, detailsMap);
      renderDNSRecords(dnsData);
      renderTLSInfo(httpsResult);
      document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 500);

  } catch (err) {
    hideProgress();
    showDomainError(`Scan failed: ${err.message || 'Unknown error. Please try again.'}`);
    UI.scanBtnMain.disabled = false;
    UI.demoBtn.disabled     = false;
  }
}

/* ==========================================================================
   DEMO DATA ENGINE
   ========================================================================== */

/**
 * Loads and renders a clearly-labeled demonstration dataset.
 * No real DNS queries are made.
 */
function loadDemo() {
  const domain = 'demo.example.com';
  UI.domainInput.value = domain;
  UI.resetBtn.classList.remove('hidden');

  showProgress();
  renderProgress(0, 'Loading demo data…');
  addProgressStep('Loading demonstration dataset…');

  let pct = 0;
  const interval = setInterval(() => {
    pct = Math.min(pct + 20, 90);
    renderProgress(pct, 'Loading demo data…');
  }, 150);

  setTimeout(() => {
    clearInterval(interval);
    renderProgress(100, 'Demo loaded!');
    addProgressStep('Demo data loaded.');
    completeProgressStep('Loading demonstration dataset…');

    // Demo checks
    const checksMap = {
      https_availability:     STATUS.PASS,
      hsts:                   STATUS.PASS,
      csp:                    STATUS.WARN,
      x_frame_options:        STATUS.PASS,
      x_content_type_options: STATUS.PASS,
      referrer_policy:        STATUS.WARN,
      permissions_policy:     STATUS.FAIL,
      spf:                    STATUS.PASS,
      dmarc:                  STATUS.WARN,
      dkim:                   STATUS.PASS,
    };

    const detailsMap = {
      https_availability: {
        status: STATUS.PASS,
        message: '[DEMO] HTTPS connection confirmed.',
        source: 'Demo Data',
        confidence: 'Demo only',
      },
      hsts: {
        status: STATUS.PASS,
        value: 'max-age=31536000; includeSubDomains',
        issues: [],
        message: '[DEMO] HSTS header present with strong configuration.',
        source: 'Demo Data',
        confidence: 'Demo only',
      },
      csp: {
        status: STATUS.WARN,
        value: "default-src 'self' 'unsafe-inline'; object-src 'none'",
        issues: ["'unsafe-inline' is present in the default-src directive."],
        message: "[DEMO] CSP found but contains 'unsafe-inline'.",
        source: 'Demo Data',
        confidence: 'Demo only',
      },
      x_frame_options: {
        status: STATUS.PASS,
        value: 'SAMEORIGIN',
        issues: [],
        message: '[DEMO] X-Frame-Options: SAMEORIGIN is set.',
        source: 'Demo Data',
        confidence: 'Demo only',
      },
      x_content_type_options: {
        status: STATUS.PASS,
        value: 'nosniff',
        issues: [],
        message: '[DEMO] X-Content-Type-Options: nosniff is set.',
        source: 'Demo Data',
        confidence: 'Demo only',
      },
      referrer_policy: {
        status: STATUS.WARN,
        value: 'origin',
        issues: ['"origin" may expose the full origin to external sites.'],
        message: "[DEMO] Referrer-Policy is set but weak.",
        source: 'Demo Data',
        confidence: 'Demo only',
      },
      permissions_policy: {
        status: STATUS.FAIL,
        value: null,
        issues: ['Header not present.'],
        message: '[DEMO] Permissions-Policy header is missing.',
        source: 'Demo Data',
        confidence: 'Demo only',
      },
      spf: {
        status: STATUS.PASS,
        record: 'v=spf1 include:_spf.google.com ~all',
        issues: [],
        message: '[DEMO] Valid SPF record found.',
        source: 'Demo Data',
        confidence: 'Demo only',
      },
      dmarc: {
        status: STATUS.WARN,
        record: 'v=DMARC1; p=none; rua=mailto:dmarc@example.com',
        policy: 'none',
        issues: ['Policy is "none" — no enforcement. Consider upgrading to quarantine or reject.'],
        message: '[DEMO] DMARC found with p=none (monitoring only).',
        source: 'Demo Data',
        confidence: 'Demo only',
      },
      dkim: {
        status: STATUS.PASS,
        value: 'google._domainkey.demo.example.com\nv=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEB…',
        issues: [],
        message: '[DEMO] DKIM record found for selector: google.',
        source: 'Demo Data',
        confidence: 'Demo only',
      },
    };

    const dnsData = {
      a:    { records: ['203.0.113.42'], error: null },
      aaaa: { records: ['2001:db8::1'],   error: null },
      mx:   { records: ['10 mail.demo.example.com.'], error: null },
      ns:   { records: ['ns1.demo.example.com.', 'ns2.demo.example.com.'], error: null },
      txt:  { records: ['v=spf1 include:_spf.google.com ~all', 'google-site-verification=abc123'], error: null },
    };

    const httpsResult = {
      httpsAvailable: STATUS.PASS,
      httpRedirect: STATUS.UNKNOWN,
      note: '[DEMO] HTTPS connection confirmed in demonstration mode.',
    };

    const scoreData = calculateRiskScore(checksMap);

    setTimeout(() => {
      hideProgress();
      showResults(true);
      renderScore(scoreData);
      renderChecksGrid(checksMap);
      renderFindings(checksMap, detailsMap);
      renderDNSRecords(dnsData);
      renderTLSInfo(httpsResult);
      document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 300);

  }, 1000);
}

/* ==========================================================================
   EVENT WIRING
   ========================================================================== */

function handleScanClick() {
  clearDomainError();
  const raw = UI.domainInput.value;
  const domain = normalizeDomain(raw);
  const error  = validateDomain(domain);

  if (error) {
    showDomainError(error);
    UI.domainInput.focus();
    return;
  }

  const dkimSel  = UI.dkimSelector.value.trim() || null;
  const rawHdrs  = UI.headersInput.value;

  runScan(domain, dkimSel, rawHdrs);
}

document.addEventListener('DOMContentLoaded', () => {
  // Both scan buttons trigger the same handler
  UI.scanBtnMain.addEventListener('click', handleScanClick);
  UI.scanBtn.addEventListener('click', handleScanClick);

  UI.demoBtn.addEventListener('click', loadDemo);
  UI.resetBtn.addEventListener('click', resetApplication);

  // Allow Enter key in domain input
  UI.domainInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleScanClick();
  });

  // Live validation — only show error after losing focus
  UI.domainInput.addEventListener('blur', () => {
    const raw    = UI.domainInput.value;
    if (!raw.trim()) return;
    const domain = normalizeDomain(raw);
    const error  = validateDomain(domain);
    if (error) showDomainError(error);
    else clearDomainError();
  });

  UI.domainInput.addEventListener('input', () => {
    clearDomainError();
  });
});
