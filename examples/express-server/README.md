# Example: Express server with ssrf middleware

This example shows how to use the library at:
- App level: global enforcement via `app.use(ssrf.middleware(...))`
- Route level: isolated instance per route via `const inst = ssrf.create(...); app.post('/r', inst.middleware(...))`

## Prerequisites

- Node.js 18+
- Install dependencies in the project root:

```powershell
npm install --no-audit --no-fund
```

## Run the server

```powershell
node .\examples\express-server\server.js
```

Server starts at http://localhost:3000

## Endpoints

- GET /check?url=<target>
  - Validates `url` from query (configured in middleware).
  - On success: `{ ok: true, safeUrl: "http://example.com" }`
  - On block: `{ error: [{ ssrf: "reason" }, ...] }` with HTTP 400

- POST /upload
  - Route-level middleware created via `ssrf.create(...)`.
  - Reads `target` from JSON body `{ "target": "..." }`.
  - On success: `{ ok: true, target: "<approved URL>" }`

## Customization

- Global middleware config lives in `server.js` inside `ssrf.middleware(options, mwOptions)`.
- Route-level example uses `uploads = ssrf.create(options)` then `uploads.middleware(mwOptions)`.
- Useful `options`:
  - `blacklistFile`, `whitelistFile` (one entry per line: host/IP/CIDR)
  - `blacklistHosts|IPs|CIDRs`, `whitelistHosts|IPs|CIDRs`
  - `path` (true = return full href, false = scheme+host)
- Useful `mwOptions`:
  - `source`: 'body' | 'query' | 'params' | 'headers'
  - `key`: field name to read from the chosen source
  - `attachKey`: property name to attach approved URL (default `safeUrl`)
  - `replaceOriginal`: overwrite `req[source][key]` with approved URL
  - `blockOnError`: respond with 400 JSON when blocked (default true)
  - `statusCode`: HTTP code to use when blocking (default 400)
  - `onError`: custom error handler `function(errors, req, res, next)`

## Notes

- Inputs can be full URLs, hostnames, raw IPv4, or raw IPv6 (bracketed automatically).
- Hostnames resolve to all A/AAAA records and each IP is evaluated.
- Private/loopback/link-local/multicast/reserved IPs are blocked unless explicitly whitelisted.
- Whitelist takes precedence; if provided, target must match it.
