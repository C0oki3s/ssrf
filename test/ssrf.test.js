/* eslint-env jest */

const path = require('path')

// Mock dns.lookup so tests don't rely on network
jest.mock('dns', () => {
  const lookup = jest.fn()
  return {
    lookup,
    ADDRCONFIG: 0,
    V4MAPPED: 0
  }
})

// Helper to set mock DNS responses
function setLookupResponses (map) {
  const dns = require('dns')
  dns.lookup.mockImplementation((host, options, cb) => {
    const arr = map[host]
    if (!arr) return cb(new Error('mock NXDOMAIN'))
    const out = arr.map(a => ({ address: a, family: a.includes(':') ? 6 : 4 }))
    cb(null, out)
  })
}

// Load library after mocks
const ssrf = require('../lib/index')

beforeEach(() => {
  jest.clearAllMocks()
  // Reset options to default state, no lists, default path=true
  ssrf.options({ path: true })
})

describe('IPv4 odd encodings (hex, octal, integer)', () => {
  test('blocks hex 0x7f000001 (127.0.0.1)', async () => {
    await expect(ssrf.url('0x7f000001')).rejects.toThrow(/Private\/Reserved IP/)
  })
  test('blocks octal dotted 0177.0.0.1 (127.0.0.1)', async () => {
    await expect(ssrf.url('0177.0.0.1')).rejects.toThrow(/Private\/Reserved IP/)
  })
  test('blocks single integer 2130706433 (127.0.0.1)', async () => {
    await expect(ssrf.url('2130706433')).rejects.toThrow(/Private\/Reserved IP/)
  })
  test('allows when whitelisted via CIDR 127.0.0.0/8', async () => {
    ssrf.options({ whitelistCIDRs: ['127.0.0.0/8'], path: false })
    await expect(ssrf.url('0x7f000001')).resolves.toBe('http://127.0.0.1')
  })
})

describe('Schema enforcement', () => {
  test('blocks non-http(s) schema', async () => {
    await expect(ssrf.url('ftp://1.1.1.1')).rejects.toThrow(/Schema Error/)
  })
})

describe('Host/IP lists and DNS resolution', () => {
  test('blocks blacklisted host', async () => {
    ssrf.options({ blacklistHosts: ['evil.com'] })
    await expect(ssrf.url('evil.com')).rejects.toThrow(/Hostname blacklisted/)
  })

  test('allows bare host resolving to public IP', async () => {
    setLookupResponses({ 'example.com': ['1.1.1.1'] })
    ssrf.options({ path: false })
    await expect(ssrf.url('example.com')).resolves.toBe('http://example.com')
  })

  test('blocks host resolving to private IP', async () => {
    setLookupResponses({ 'intranet.local': ['10.1.2.3'] })
    await expect(ssrf.url('intranet.local')).rejects.toThrow(/Private\/Reserved IP/)
  })

  test('allows private IP when whitelisted by CIDR', async () => {
    setLookupResponses({ 'intranet.local': ['10.1.2.3'] })
    ssrf.options({ whitelistCIDRs: ['10.0.0.0/8'], path: false })
    await expect(ssrf.url('intranet.local')).resolves.toBe('http://intranet.local')
  })
})

describe('Express middleware factory', () => {
  const makeReqRes = (source = 'body', key = 'url', value = '1.1.1.1') => {
    const req = { body: {}, query: {}, params: {}, headers: {} }
    if (source === 'headers') req.headers[key] = value
    else req[source][key] = value
    const res = {
      _status: null,
      _json: null,
      status (s) { this._status = s; return this },
      json (p) { this._json = p; return this }
    }
    const next = jest.fn()
    return { req, res, next }
  }

  test('middleware attaches safeUrl and calls next on allow', async () => {
    setLookupResponses({ 'example.com': ['1.1.1.1'] })
    const mw = ssrf.middleware({ path: false }, { source: 'query', key: 'url', attachKey: 'safeUrl' })
    const { req, res, next } = makeReqRes('query', 'url', 'example.com')
    await mw(req, res, next)
    expect(req.safeUrl).toBe('http://example.com')
    expect(next).toHaveBeenCalled()
  })

  test('middleware blocks and responds 400 on deny', async () => {
    const mw = ssrf.middleware({}, { source: 'body', key: 'url', attachKey: 'safeUrl' })
    const { req, res, next } = makeReqRes('body', 'url', '::1')
    await mw(req, res, next)
    expect(res._status).toBe(400)
    expect(res._json).toBeTruthy()
    expect(next).not.toHaveBeenCalled()
  })
})

describe('IPv6 CIDR allow/deny behavior', () => {
  test('blocks raw IPv6 loopback ::1', async () => {
    await expect(ssrf.url('::1')).rejects.toThrow(/Private\/Reserved IP/)
  })

  test('blocks host resolving to unique-local fc00::1 without whitelist', async () => {
    setLookupResponses({ 'v6.local': ['fc00::1'] })
    await expect(ssrf.url('v6.local')).rejects.toThrow(/Private\/Reserved IP/)
  })

  test('allows host resolving to unique-local when whitelisted by CIDR fc00::/7', async () => {
    setLookupResponses({ 'v6.local': ['fc00::1'] })
    ssrf.options({ whitelistCIDRs: ['fc00::/7'], path: false })
    await expect(ssrf.url('v6.local')).resolves.toBe('http://v6.local')
  })

  test('allows public IPv6 target', async () => {
    setLookupResponses({ 'v6.example': ['2001:4860:4860::8888'] })
    ssrf.options({ path: false })
    await expect(ssrf.url('v6.example')).resolves.toBe('http://v6.example')
  })

  test('blocks IP by IPv6 blacklist CIDR', async () => {
    setLookupResponses({ 'google-v6': ['2001:4860:4860::8888'] })
    ssrf.options({ blacklistCIDRs: ['2001:4860::/32'] })
    await expect(ssrf.url('google-v6')).rejects.toThrow(/IP blacklisted/)
  })
})
