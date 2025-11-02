const path = require("path")
const ssrf = require("../lib/index")
const axios = require("axios").default

// Centralized options builder to demonstrate all features.
const buildOptions = () => ({
  // Load denylist from file (supports host/IP/CIDR; '#' for comments)
  blacklistFile: path.join(__dirname, "host.txt"),

  // Allowlist/denylist via arrays
  whitelistHosts: [
    // "api.example.com",
  ],
  whitelistIPs: [
    // "203.0.113.10",
  ],
  whitelistCIDRs: [
    // "203.0.113.0/24", "2001:db8::/32"
  ],
  blacklistHosts: [
    // "evil.com",
  ],
  blacklistIPs: [
    // "13.54.97.2",
  ],
  blacklistCIDRs: [
    // "10.0.0.0/8", "fc00::/7"
  ],

  // Return only scheme+host when false; include path+query when true
  path: false
})

// Apply options
ssrf.options(buildOptions())

// Inputs to demo various cases
const samples = [
  { label: "Blacklist host (file)", value: "http://evil.com" },
  { label: "Blacklist IP (file)", value: "http://13.54.97.2" },
  { label: "Bare host", value: "example.com" },
  { label: "Bare IPv4", value: "1.1.1.1" },
  { label: "DNS rebinding demo", value: "https://c0okie.xyz/attacker.html" },
  { label: "Hex IPv4 (loopback)", value: "0x7f000001" },
  { label: "Octal dotted IPv4 (loopback)", value: "0177.0.0.1" },
  { label: "Integer IPv4 (loopback)", value: "2130706433" },
  { label: "Raw IPv6 loopback", value: "::1" },
  { label: "Bracketed IPv6", value: "http://[2001:4860:4860::8888]" }
]

// User-friendly wrapper to get a safe URL or a structured error
async function getSafeUrl(input) {
  try {
    const safe = await ssrf.url(input)
    return { ok: true, url: safe }
  } catch (e) {
    // Library throws a JSON array of reasons; try to parse, else return message
    try {
      const reasons = JSON.parse(String(e.message || e))
      return { ok: false, error: reasons }
    } catch {
      return { ok: false, error: [{ ssrf: String(e) }] }
    }
  }
}

// Axios example (optional). Only performs the request when allowed.
async function fetchIfAllowed(input) {
  const res = await getSafeUrl(input)
  if (!res.ok) {
    console.log(`[Blocked] ${input}:`, res.error)
    return
  }
  console.log(`[Allowed] ${input} ->`, res.url)
  // Uncomment to actually fetch:
  // try {
  //   const r = await axios.get(res.url)
  //   console.log("Status:", r.status)
  // } catch (err) {
  //   console.error("Fetch error:", err.message)
  // }
}

;(async () => {
  for (const s of samples) {
    await fetchIfAllowed(s.value)
  }
})()
 


