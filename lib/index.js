const dns = require('dns')
const fs = require('fs')
const ipAddress = require('ipaddr.js')

// Public API object
const ssrf = {}

// Internal state
let INPUT_RAW
let PARSED_URL
let RETURN_WITH_PATH = true

// User lists (hosts, IPs, CIDRs)
const user_blacklist = { hosts: new Set(), ips: new Set(), cidrs: [] }
const user_whitelist = { hosts: new Set(), ips: new Set(), cidrs: [] }

ssrf.options = ({
  // Back-compat: a single file path of entries to blacklist (hosts/IPs/CIDRs)
  blacklist,
  // New: explicit file paths
  blacklistFile,
  whitelistFile,
  // New: arrays for direct configuration
  blacklistHosts,
  blacklistIPs,
  blacklistCIDRs,
  whitelistHosts,
  whitelistIPs,
  whitelistCIDRs,
  // Whether to keep path/query in returned URL; default true
  path
} = {}) => {
  // Reset lists if options called again
  clearList(user_blacklist)
  clearList(user_whitelist)

  // File-based list loading
  const blFile = blacklistFile || blacklist // support old key "blacklist" as file path
  if (blFile !== undefined) {
    const parsed = loadListFile(blFile)
    mergeLists(user_blacklist, parsed)
  }
  if (whitelistFile !== undefined) {
    const parsed = loadListFile(whitelistFile)
    mergeLists(user_whitelist, parsed)
  }

  // Array-based configuration
  mergeLists(user_blacklist, normalizeRawLists({
    hosts: blacklistHosts,
    ips: blacklistIPs,
    cidrs: blacklistCIDRs
  }))
  mergeLists(user_whitelist, normalizeRawLists({
    hosts: whitelistHosts,
    ips: whitelistIPs,
    cidrs: whitelistCIDRs
  }))

  if (path !== undefined) {
    RETURN_WITH_PATH = !!path
  }
}

ssrf.url = async (urlOrIp) => {
  INPUT_RAW = urlOrIp
  // Normalize and parse the input
  PARSED_URL = normalizeAndParseInput(INPUT_RAW)

  // Validate and enforce lists
  const errorList = await evaluatePolicies()
  if (errorList && errorList.length) {
    throw new Error(JSON.stringify(errorList))
  }

  // Return either full href or just origin
  if (RETURN_WITH_PATH === false) {
    return `${PARSED_URL.protocol}//${PARSED_URL.hostname}`
  }
  return PARSED_URL.href
}

// Parse input robustly and guard against userinfo (@) confusion
function normalizeAndParseInput (input) {
  let candidate = String(input || '').trim()
  if (!candidate) {
    throw new Error('Empty input')
  }

  // If input is just an IP or hostname without scheme, prefix with http:// for parsing
  const hasScheme = /:\/\//.test(candidate)
  if (!hasScheme) {
    // If raw IPv6 address, bracket it
    if (ipAddress.isValid(candidate)) {
      try {
        const parsed = ipAddress.parse(candidate)
        if (parsed.kind && parsed.kind() === 'ipv6') {
          candidate = `http://[${candidate}]`
        } else {
          candidate = `http://${candidate}`
        }
      } catch (_) {
        candidate = `http://${candidate}`
      }
    } else {
      candidate = `http://${candidate}`
    }
  }

  // WHATWG URL parser is resilient and handles userinfo correctly
  let u
  try {
    u = new URL(candidate)
  } catch (e) {
    throw new Error('Invalid URL')
  }

  // Force hostname to be present
  if (!u.hostname) {
    throw new Error('Invalid host')
  }
  return u
}

// Checks if IP is globally routable (unicast)
function isPublicUnicast (ip) {
  if (!ipAddress.isValid(ip)) return false
  try {
    const address = ipAddress.parse(ip)
    return address.range() === 'unicast'
  } catch (_) {
    return false
  }
}

const CheckSchema = () => {
  // Allow only http and https
  return PARSED_URL.protocol === 'http:' || PARSED_URL.protocol === 'https:'
}

const evaluatePolicies = async () => {
  const errs = []

  // 1) Schema check
  if (!CheckSchema()) errs.push({ ssrf: 'Schema Error' })
  if (errs.length) return errs

  const hostname = PARSED_URL.hostname

  // 2) Hostname blacklist/whitelist checks
  if (user_whitelist.hosts.size > 0 && !user_whitelist.hosts.has(hostname)) {
    errs.push({ ssrf: 'Hostname not whitelisted' })
    return errs
  }
  if (user_blacklist.hosts.has(hostname)) {
    errs.push({ ssrf: 'Hostname blacklisted' })
    return errs
  }

  // 3) Resolve addresses (or use literal IP) and apply IP/CIDR rules
  let addrs = []
  // Handle non-decimal representations (octal/hex/integer) for IPv4
  const weirdIPv4 = normalizePossiblyNonDecimalIPv4(hostname)
  if (weirdIPv4) {
    addrs = [weirdIPv4]
  } else if (ipAddress.isValid((hostname || '').trim())) {
    addrs = [hostname.trim()]
  } else {
    // Fallback: if URL.host is bracketed IPv6, extract and use directly
    const hostField = PARSED_URL.host || ''
    const m = hostField.match(/^\[(.*)\](:\d+)?$/)
    if (m && ipAddress.isValid(m[1])) {
      addrs = [m[1]]
    }
  }

  if (!addrs.length) {
    try {
      addrs = await lookupAll(hostname)
    } catch (e) {
      errs.push({ ssrf: 'DNS Resolution Failed' })
      return errs
    }
  }

  // 4) For each address, ensure not blacklisted and is allowed. If whitelist specified, at least one must match.
  let hasWhitelistedIP = user_whitelist.ips.size === 0 && user_whitelist.cidrs.length === 0
  for (const ip of addrs) {
    const isInWhite = isIpInLists(ip, user_whitelist)
    const isInBlack = isIpInLists(ip, user_blacklist)

    if (isInBlack) {
      errs.push({ ssrf: 'IP blacklisted', ip })
      return errs
    }

    if (isInWhite) hasWhitelistedIP = true

    // Block private/reserved/etc unless whitelisted
    if (!isInWhite && !isPublicUnicast(ip)) {
      errs.push({ ssrf: 'Private/Reserved IP', ip })
      return errs
    }
  }

  if (!hasWhitelistedIP) {
    errs.push({ ssrf: 'No IP matches whitelist' })
    return errs
  }

  return errs
}

async function lookupAll (host) {
  return new Promise((resolve, reject) => {
    dns.lookup(host, { all: true }, (err, addresses) => {
      if (err) return reject(err)
      const out = (addresses || []).map(a => a.address)
      resolve(out)
    })
  })
}

// Helpers for list management and matching
function clearList (list) {
  list.hosts.clear()
  list.ips.clear()
  list.cidrs.length = 0
}

function mergeLists (dst, src) {
  if (!src) return
  if (src.hosts) for (const h of src.hosts) dst.hosts.add(h)
  if (src.ips) for (const ip of src.ips) dst.ips.add(ip)
  if (src.cidrs) dst.cidrs.push(...src.cidrs)
}

function normalizeRawLists ({ hosts, ips, cidrs } = {}) {
  const out = { hosts: [], ips: [], cidrs: [] }
  if (Array.isArray(hosts)) out.hosts = hosts.filter(Boolean).map(String)
  if (Array.isArray(ips)) out.ips = ips.filter(ipAddress.isValid)
  if (Array.isArray(cidrs)) out.cidrs = cidrs.map(parseCidrSafe).filter(Boolean)
  return out
}

function loadListFile (filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8')
    const lines = raw.replace(/\r\n/g, '\n').split('\n')
    const out = { hosts: [], ips: [], cidrs: [] }
    for (const lineRaw of lines) {
      const line = lineRaw.trim()
      if (!line || line.startsWith('#')) continue
      // CIDR
      const cidr = parseCidrSafe(line)
      if (cidr) {
        out.cidrs.push(cidr)
        continue
      }
      // IP
      if (ipAddress.isValid(line)) {
        out.ips.push(line)
        continue
      }
      // Hostname/domain
      out.hosts.push(line.toLowerCase())
    }
    return out
  } catch (err) {
    throw new Error('File does not Exists')
  }
}

function parseCidrSafe (str) {
  if (typeof str !== 'string' || !str.includes('/')) return null
  try {
    const [addr, range] = ipAddress.parseCIDR(str)
    return [addr, range]
  } catch (_) {
    return null
  }
}

function isIpInLists (ip, list) {
  if (!ipAddress.isValid(ip)) return false
  if (list.ips.has(ip)) return true
  try {
    const addr = ipAddress.parse(ip)
    for (const cidr of list.cidrs) {
      if (addr.match(cidr)) return true
    }
  } catch (_) {
    return false
  }
  return false
}

// Parse IPv4 supplied in octal/hex/decimal (dotted or single-integer) and
// return canonical dotted-decimal string if valid; otherwise null.
function normalizePossiblyNonDecimalIPv4 (input) {
  if (typeof input !== 'string') return null
  const s = input.trim()
  if (!s) return null

  // Reject if contains characters invalid for these forms (allow 0-9a-fxod.)
  // but don't be overly strict; we will validate during parsing.

  // Dotted form
  const parts = s.split('.')
  if (parts.length > 1 && parts.length <= 4) {
    const nums = []
    for (let i = 0; i < parts.length; i++) {
      const val = parseIPv4Component(parts[i])
      if (val == null || val < 0) return null
      nums.push(val)
    }
    // inet_aton style expansion
    let value
    if (nums.length === 4) {
      if (nums.some(n => n > 255)) return null
      value = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
    } else if (nums.length === 3) {
      if (nums[0] > 255 || nums[1] > 255 || nums[2] > 0xFFFF) return null
      value = (nums[0] << 24) | (nums[1] << 16) | nums[2]
    } else if (nums.length === 2) {
      if (nums[0] > 255 || nums[1] > 0xFFFFFF) return null
      value = (nums[0] << 24) | nums[1]
    } else { // length 1 handled below as integer form
      value = nums[0]
    }
    if (!Number.isFinite(value) || value < 0 || value > 0xFFFFFFFF) return null
    return intToIPv4(value >>> 0)
  }

  // Single integer form (decimal, octal, or hex)
  const intVal = parseIPv4Integer(s)
  if (intVal == null) return null
  return intToIPv4(intVal >>> 0)
}

function intToIPv4 (v) {
  const b1 = (v >>> 24) & 0xFF
  const b2 = (v >>> 16) & 0xFF
  const b3 = (v >>> 8) & 0xFF
  const b4 = v & 0xFF
  return `${b1}.${b2}.${b3}.${b4}`
}

function parseIPv4Component (token) {
  if (token === '') return null
  const base = detectBase(token)
  const clean = stripBasePrefix(token, base)
  const re = base === 16 ? /^[0-9a-fA-F]+$/ : base === 8 ? /^[0-7]+$/ : /^\d+$/
  if (!re.test(clean)) return null
  const val = parseInt(clean, base)
  if (!Number.isFinite(val)) return null
  return val
}

function parseIPv4Integer (token) {
  const base = detectBase(token)
  const clean = stripBasePrefix(token, base)
  const re = base === 16 ? /^[0-9a-fA-F]+$/ : base === 8 ? /^[0-7]+$/ : /^\d+$/
  if (!re.test(clean)) return null
  const val = parseInt(clean, base)
  if (!Number.isFinite(val) || val < 0 || val > 0xFFFFFFFF) return null
  return val
}

function detectBase (token) {
  if (/^0x/i.test(token)) return 16
  if (/^0o/i.test(token)) return 8
  // Leading 0 with only octal digits -> octal (classic form)
  if (/^0[0-7]+$/.test(token)) return 8
  return 10
}

function stripBasePrefix (token, base) {
  if (base === 16) return token.replace(/^0x/i, '')
  if (base === 8) return token.replace(/^0o/i, '')
  return token
}

module.exports = ssrf

// --------------------
// Express-style middleware support
// --------------------

// Build immutable config from options
function buildConfigFromOptions (opts = {}) {
  const cfg = {
    lists: {
      blacklist: { hosts: new Set(), ips: new Set(), cidrs: [] },
      whitelist: { hosts: new Set(), ips: new Set(), cidrs: [] }
    },
    returnWithPath: opts.path !== undefined ? !!opts.path : true
  }
  const blFile = opts.blacklistFile || opts.blacklist
  if (blFile !== undefined) mergeLists(cfg.lists.blacklist, loadListFile(blFile))
  if (opts.whitelistFile !== undefined) mergeLists(cfg.lists.whitelist, loadListFile(opts.whitelistFile))
  mergeLists(cfg.lists.blacklist, normalizeRawLists({ hosts: opts.blacklistHosts, ips: opts.blacklistIPs, cidrs: opts.blacklistCIDRs }))
  mergeLists(cfg.lists.whitelist, normalizeRawLists({ hosts: opts.whitelistHosts, ips: opts.whitelistIPs, cidrs: opts.whitelistCIDRs }))
  return cfg
}

function CheckSchemaWith (u) {
  return u.protocol === 'http:' || u.protocol === 'https:'
}

async function evaluatePoliciesWith (u, lists) {
  const errs = []
  if (!CheckSchemaWith(u)) errs.push({ ssrf: 'Schema Error' })
  if (errs.length) return errs

  const hostname = u.hostname

  if (lists.whitelist.hosts.size > 0 && !lists.whitelist.hosts.has(hostname)) {
    errs.push({ ssrf: 'Hostname not whitelisted' })
    return errs
  }
  if (lists.blacklist.hosts.has(hostname)) {
    errs.push({ ssrf: 'Hostname blacklisted' })
    return errs
  }

  let addrs = []
  const weirdIPv4 = normalizePossiblyNonDecimalIPv4(hostname)
  if (weirdIPv4) {
    addrs = [weirdIPv4]
  } else if (ipAddress.isValid((hostname || '').trim())) {
    addrs = [hostname.trim()]
  } else {
    const hostField = u.host || ''
    const m = hostField.match(/^\[(.*)\](:\d+)?$/)
    if (m && ipAddress.isValid(m[1])) {
      addrs = [m[1]]
    }
  }
  if (!addrs.length) {
    try {
      addrs = await lookupAll(hostname)
    } catch (e) {
      return [{ ssrf: 'DNS Resolution Failed' }]
    }
  }

  let hasWhitelistedIP = lists.whitelist.ips.size === 0 && lists.whitelist.cidrs.length === 0
  for (const ip of addrs) {
    const isInWhite = isIpInLists(ip, lists.whitelist)
    const isInBlack = isIpInLists(ip, lists.blacklist)
    if (isInBlack) return [{ ssrf: 'IP blacklisted', ip }]
    if (isInWhite) hasWhitelistedIP = true
    if (!isInWhite && !isPublicUnicast(ip)) return [{ ssrf: 'Private/Reserved IP', ip }]
  }
  if (!hasWhitelistedIP) return [{ ssrf: 'No IP matches whitelist' }]

  return errs
}

async function validateAndFormat (input, config) {
  const u = normalizeAndParseInput(input)
  const errs = await evaluatePoliciesWith(u, config.lists)
  if (errs.length) return { ok: false, errors: errs }
  const href = config.returnWithPath ? u.href : `${u.protocol}//${u.hostname}`
  return { ok: true, url: href }
}

function extractInputFromReq (req, source = 'body', key = 'url') {
  try {
    if (source === 'headers') return req && req.headers ? req.headers[key.toLowerCase()] : undefined
    return req && req[source] ? req[source][key] : undefined
  } catch (_) {
    return undefined
  }
}

function makeMiddleware (config, mw = {}) {
  const {
    source = 'body',
    key = 'url',
    attachKey = 'safeUrl',
    replaceOriginal = false,
    blockOnError = true,
    statusCode = 400,
    onError
  } = mw

  return async function ssrfMiddleware (req, res, next) {
    const input = extractInputFromReq(req, source, key)
    if (!input) {
      const errs = [{ ssrf: 'Empty input' }]
      if (onError) return onError(errs, req, res, next)
      if (blockOnError) return res && res.status ? res.status(statusCode).json({ error: errs }) : next(errs)
      req[attachKey] = null
      return next()
    }
    const result = await validateAndFormat(input, config)
    if (!result.ok) {
      if (onError) return onError(result.errors, req, res, next)
      if (blockOnError) return res && res.status ? res.status(statusCode).json({ error: result.errors }) : next(result.errors)
      req[attachKey] = null
      return next()
    }
    req[attachKey] = result.url
    try {
      if (replaceOriginal && req[source]) req[source][key] = result.url
    } catch (_) {}
    return next()
  }
}

// Factory that returns an isolated instance (preferred for endpoint-level config)
ssrf.create = function create (options = {}) {
  const config = buildConfigFromOptions(options)
  return {
    url: async (input) => {
      const r = await validateAndFormat(input, config)
      if (!r.ok) throw new Error(JSON.stringify(r.errors))
      return r.url
    },
    middleware: (mwOptions = {}) => makeMiddleware(config, mwOptions)
  }
}

// App-level convenience: app.use(ssrf.middleware(options, mwOptions))
ssrf.middleware = function middleware (options = {}, mwOptions = {}) {
  const config = buildConfigFromOptions(options)
  return makeMiddleware(config, mwOptions)
}
