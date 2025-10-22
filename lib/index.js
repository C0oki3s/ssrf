const dns = require('dns')
const fs = require('fs')
const ipAddress = require('ipaddr.js')

// Module configuration (not per-call state)
const config = {
  blacklist: [], // array of lowercase hostnames or IPs as strings (normalized, brackets stripped)
  allowlist: [], // optional allowlist; when non-empty, only these hosts/IPs are allowed
  path: true, // when false, only return origin (protocol + host[:port])
  blockRanges: null, // optional Set of ipaddr.js range() strings to block; when null, blocks all non-unicast
  cidrAllow: [], // parsed CIDR networks to allow (each item: [addr, prefix])
  cidrDeny: [], // parsed CIDR networks to deny
  portAllowlist: null // optional Set of allowed ports; null => allow all
}

const ssrf = {}

// Public API: Configure module
ssrf.options = ({
  blacklist, /** Accepts absolute path to file OR an array of hosts/IPs */
  whitelist, allowlist, /** Accepts absolute path or array; allowlist takes precedence over whitelist */
  path,
  blockRanges, /** Array of ipaddr.js range names to block (e.g., ['private','loopback']) */
  cidrAllow, /** Array of CIDR strings to allow; if provided, all resolved IPs must fall within at least one */
  cidrDeny, /** Array of CIDR strings to deny; if any resolved IP falls within one, it's blocked */
  portAllowlist /** Array of allowed port numbers; if provided, URL port (or default) must be in this set */
} = {}) => {
  // Load/assign blacklist
  if (blacklist !== undefined) {
    if (Array.isArray(blacklist)) {
      config.blacklist = normalizeList(blacklist)
    } else if (typeof blacklist === 'string') {
      try {
        const content = fs.readFileSync(blacklist, 'utf8')
        config.blacklist = normalizeList(content.replace(/\r\n/g, '\n').split('\n'))
      } catch (error) {
        throw new Error('File does not Exists')
      }
    } else {
      throw new Error('Invalid blacklist: expected file path or array')
    }
  }
  // Load/assign allowlist (aka whitelist)
  const wl = allowlist !== undefined ? allowlist : whitelist
  if (wl !== undefined) {
    if (Array.isArray(wl)) {
      config.allowlist = normalizeList(wl)
    } else if (typeof wl === 'string') {
      try {
        const content = fs.readFileSync(wl, 'utf8')
        config.allowlist = normalizeList(content.replace(/\r\n/g, '\n').split('\n'))
      } catch (error) {
        throw new Error('File does not Exists')
      }
    } else {
      throw new Error('Invalid allowlist: expected file path or array')
    }
  }
  // Configure path behavior
  if (typeof path === 'boolean') {
    config.path = path
  }
  // Configure block ranges
  if (blockRanges !== undefined) {
    if (Array.isArray(blockRanges)) {
      config.blockRanges = new Set(blockRanges.map(String))
    } else {
      throw new Error('Invalid blockRanges: expected array of range names')
    }
  }
  // Configure CIDR allow/deny
  if (cidrAllow !== undefined) {
    if (Array.isArray(cidrAllow)) config.cidrAllow = parseCidrs(cidrAllow)
    else throw new Error('Invalid cidrAllow: expected array of CIDR strings')
  }
  if (cidrDeny !== undefined) {
    if (Array.isArray(cidrDeny)) config.cidrDeny = parseCidrs(cidrDeny)
    else throw new Error('Invalid cidrDeny: expected array of CIDR strings')
  }
  // Configure port allowlist
  if (portAllowlist !== undefined) {
    if (Array.isArray(portAllowlist)) {
      const nums = portAllowlist.map((p) => Number(p)).filter((n) => Number.isInteger(n) && n >= 0 && n <= 65535)
      config.portAllowlist = new Set(nums)
    } else {
      throw new Error('Invalid portAllowlist: expected array of numbers')
    }
  }
}

// Public API: Validate and return a safe URL string
ssrf.url = async (input) => {
  const issues = []

  // Parse with WHATWG URL
  let urlObj
  try {
    urlObj = new URL(input)
  } catch (e) {
    issues.push({ ssrf: 'Invalid URL' })
    throw new Error(JSON.stringify(issues))
  }

  // Schema check: only http/https
  if (!isAllowedProtocol(urlObj)) {
    issues.push({ ssrf: 'Schema Error' })
    throw new Error(JSON.stringify(issues))
  }

  // Normalize host (lowercase, strip IPv6 brackets) for DNS and comparisons
  const rawHost = (urlObj.hostname || '').toLowerCase()
  const hostname = stripIPv6Brackets(rawHost)
  const normalizedIp = normalizeObfuscatedIPv4(hostname)
  const hostForChecks = normalizedIp || hostname

  // Port allowlist check (if configured)
  if (config.portAllowlist instanceof Set) {
    const port = getPort(urlObj)
    if (!config.portAllowlist.has(port)) {
      issues.push({ ssrf: 'Port Policy Error' })
      throw new Error(JSON.stringify(issues))
    }
  }

  // Blacklist check (exact match)
  if (config.blacklist.length) {
    for (const blocked of config.blacklist) {
      if (hostForChecks === stripIPv6Brackets(blocked)) {
        issues.push({ ssrf: 'Blacklist Error' })
        break
      }
      // If blacklist entry is an IP literal and hostname resolves to that IP, the DNS check will catch it
    }
    if (issues.length) throw new Error(JSON.stringify(issues))
  }

  // Allowlist check (if provided): must match to proceed
  if (config.allowlist.length) {
    let allowed = false
    for (const allowedHost of config.allowlist) {
      if (hostForChecks === stripIPv6Brackets(allowedHost)) {
        allowed = true
        break
      }
    }
    if (!allowed) {
      issues.push({ ssrf: 'Allowlist Error' })
      throw new Error(JSON.stringify(issues))
    }
  }

  // DNS/IP checks to prevent private/rfc1918/loopback etc. (basic DNS rebinding mitigation)
  try {
  const ips = await resolveAll(hostForChecks)

    // If no records found, treat as error
    if (!ips.length) {
      issues.push({ ssrf: 'DNS Resolution Failed' })
    }

    for (const ip of ips) {
      // CIDR deny takes precedence if provided
      if (config.cidrDeny.length && isInAnyCidr(ip, config.cidrDeny)) {
        issues.push({ ssrf: 'CIDR Deny Error' })
        break
      }
      if (!isPublicUnicast(ip)) {
        issues.push({ ssrf: 'Private IP Lookup' })
        break
      }
    }

    // CIDR allow: all IPs must be in allowed CIDR(s)
    if (!issues.length && config.cidrAllow.length) {
      for (const ip of ips) {
        if (!isInAnyCidr(ip, config.cidrAllow)) {
          issues.push({ ssrf: 'CIDR Allow Error' })
          break
        }
      }
    }
  } catch (err) {
    issues.push({ ssrf: 'Catch Block' })
  }

  if (issues.length) {
    throw new Error(JSON.stringify(issues))
  }

  // Return sanitized URL
  if (config.path === false) {
    // Include port when present
    return urlObj.origin
  }
  return urlObj.href
}

// Helpers
function normalizeList (list) {
  return list
    .map((s) => stripIPv6Brackets((s || '').toString().trim().toLowerCase()))
    .filter((s) => s.length > 0)
}

function isAllowedProtocol (urlObj) {
  return urlObj.protocol === 'http:' || urlObj.protocol === 'https:'
}

function getPort (urlObj) {
  if (urlObj.port) return Number(urlObj.port)
  return urlObj.protocol === 'https:' ? 443 : 80
}

function isPublicUnicast (ip) {
  // Validate
  if (!ipAddress.isValid(ip)) return false
  try {
    const addr = ipAddress.parse(ip)
    const range = addr.range() // 'unicast', 'private', 'loopback', 'linkLocal', 'multicast', 'reserved', 'uniqueLocal', etc.
    if (config.blockRanges instanceof Set) {
      return !config.blockRanges.has(range)
    }
    return range === 'unicast'
  } catch (e) {
    return false
  }
}

async function resolveAll (hostname) {
  // If the hostname is already an IP literal, just return it
  if (ipAddress.isValid(hostname)) return [hostname]

  const results = []
  const p = dns.promises
  // Resolve A and AAAA; ignore errors per family and continue
  try {
    const v4 = await p.resolve4(hostname)
    results.push(...v4)
  } catch {}
  try {
    const v6 = await p.resolve6(hostname)
    results.push(...v6)
  } catch {}

  // Fallback: dns.lookup if resolvers are blocked
  if (!results.length) {
    const address = await new Promise((resolve, reject) => {
      dns.lookup(hostname, { all: false, family: 0, hints: dns.ADDRCONFIG | dns.V4MAPPED }, (err, address) => {
        if (err) return reject(err)
        resolve(address)
      })
    })
    if (typeof address === 'string') results.push(address)
    else if (address && address.address) results.push(address.address)
  }

  return results
}

function stripIPv6Brackets (host) {
  if (host.startsWith('[') && host.endsWith(']')) {
    return host.slice(1, -1)
  }
  return host
}

// Attempt to normalize IPv4 provided in hex/octal/short/dword notations
function normalizeObfuscatedIPv4 (host) {
  // Pure integer (dword)
  if (/^\d+$/.test(host)) {
    const n = Number(host)
    if (Number.isSafeInteger(n) && n >= 0 && n <= 0xFFFFFFFF) {
      return fromDword(n)
    }
  }
  // Pure hex dword e.g. 0x7f000001
  if (/^0x[0-9a-f]+$/i.test(host)) {
    const n = Number(host)
    if (Number.isSafeInteger(n) && n >= 0 && n <= 0xFFFFFFFF) {
      return fromDword(n)
    }
  }
  // Dotted parts possibly hex/octal/dec, with legacy shortening
  if (host.includes('.')) {
    const parts = host.split('.')
    if (parts.every(p => p.length > 0)) {
      const nums = parts.map(parseFlexible)
      if (nums.every(x => x !== null && x >= 0)) {
        let dword = null
        if (nums.length === 4) {
          if (nums.every(x => x <= 255)) dword = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
        } else if (nums.length === 3) {
          if (nums[0] <= 255 && nums[1] <= 255 && nums[2] <= 0xFFFF) dword = (nums[0] << 24) | (nums[1] << 16) | nums[2]
        } else if (nums.length === 2) {
          if (nums[0] <= 255 && nums[1] <= 0xFFFFFF) dword = (nums[0] << 24) | nums[1]
        } else if (nums.length === 1) {
          if (nums[0] <= 0xFFFFFFFF) dword = nums[0]
        }
        if (dword !== null) return fromDword(dword >>> 0)
      }
    }
  }
  return null
}

function parseFlexible (s) {
  if (/^0x[0-9a-f]+$/i.test(s)) return parseInt(s, 16)
  if (/^0[0-7]+$/.test(s)) return parseInt(s, 8)
  if (/^\d+$/.test(s)) return parseInt(s, 10)
  return null
}

function fromDword (n) {
  const a = (n >>> 24) & 0xFF
  const b = (n >>> 16) & 0xFF
  const c = (n >>> 8) & 0xFF
  const d = n & 0xFF
  return `${a}.${b}.${c}.${d}`
}

function parseCidrs (list) {
  const out = []
  for (const item of list) {
    const s = String(item).trim()
    if (!s) continue
    try {
      const parsed = ipAddress.parseCIDR(s)
      out.push(parsed)
    } catch (e) {
      throw new Error(`Invalid CIDR: ${s}`)
    }
  }
  return out
}

function isInAnyCidr (ip, cidrs) {
  try {
    const addr = ipAddress.parse(ip)
    for (const [net, prefix] of cidrs) {
      if (addr.kind() !== net.kind()) continue
      if (addr.match([net, prefix])) return true
    }
  } catch {
    return false
  }
  return false
}

module.exports = ssrf
