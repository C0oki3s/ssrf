## ssrf

[![NPM Version][ssrf-badgen]][download-url]
![LICENSE](https://badgen.net/badge/license/MIT/blue)

## Server-Side Request Forgery (SSRF)
the attacker can abuse functionality on the server to read or update internal resources. The attacker can supply or modify a URL which the code running on the server will read or submit data to, and by carefully selecting the URLs, the attacker may be able to read server configuration such as AWS metadata, connect to internal services like http enabled databases or perform post requests towards internal services which are not intended to be exposed [read more](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)

## Install
`npm install ssrf`

## Usage

```js
// Back-compat usage (direct API)
ssrf.options({
  blacklist: "/ssrf/list.txt", // Linux; on Windows use 'C:\\Users\\host.txt'
  path: false
})
const gotssrf = await ssrf.url("http://13.54.97.2")
``` 

## ssrf.url()

ssrf.url return Promise so use await ssrf.url("http://example.com") in try-catch block
     
```js
     
try{
        const result = await ssrf.url(url)
        //do stuff if success
}catch{
        //do stuff if fail
} 
```

### ssrf.options({})

options takes two argument 
  + blacklist 
  + path

#### blacklist

Blacklist parameter takes input of absolute path to a text file 
 Ex:- /usr/list/blacklist.txt (Linux)
 C:\\Users\\host.txt (windows)
 By default it don't have any blacklist but if an user passes absolute path then it reads file and run a for loop everytime it hits middleware
        
   
##### File format 

```
evil.com
example.com
87.26.7.9
98.72.6.2
```
                
      
#### path

Path parameter taker A Boolean value as (true or false)
Where by default its True which means it will return /path and ?parameters attached to Host 

`Ex:- if a user send's http://example.com/path1?param=1 return http://example.com/path1?param=1`
          
    
##### True

return absolute Url `http://example.com/path1?param=1`
      
##### False

return  Hostname `http://example.com or http://www.example.com`

This module Prevents From reserverd character `@` attack and DNS rebinding attack. to Learn more about DNS rebinding [more](https://github.com/C0oki3s/research/tree/main/DNS-Rebinding)
           
          

[download-url]: https://www.npmjs.com/package/ssrf
[ssrf-badgen]: https://badgen.net/npm/v/ssrf
 
## Advanced configuration (CIDR, whitelist, IP inputs)

The library now supports allow/deny lists using hostnames, IPs, and CIDR ranges, from files or arrays, and accepts raw IPs/hosts as inputs.

Examples:

```js
const path = require('path')
const ssrf = require('ssrf')

ssrf.options({
  // Load lists from files (one entry per line; supports host/IP/CIDR; lines starting with # are comments)
  blacklistFile: path.join(__dirname, 'blacklist.txt'),
  whitelistFile: path.join(__dirname, 'whitelist.txt'),

  // Or configure directly
  blacklistHosts: ['evil.com'],
  blacklistIPs: ['13.54.97.2'],
  blacklistCIDRs: ['10.0.0.0/8', 'fd00::/8'],

  whitelistHosts: ['api.example.com'],
  whitelistIPs: ['203.0.113.10'],
  whitelistCIDRs: ['203.0.113.0/24', '2001:db8::/32'],

  // Return only scheme+host when false (defaults to true for full URL)
  path: false
})

// Inputs can be full URLs, hostnames, or raw IPs
await ssrf.url('http://api.example.com/v1?q=1') // allowed if matches whitelist
await ssrf.url('evil.com') // throws if blacklisted
await ssrf.url('13.54.97.2') // throws if blacklisted or not whitelisted
```

Notes:
- Only http and https schemes are permitted.
- Inputs can be full URLs, hostnames, raw IPv4, or raw IPv6. Raw IPv6 is normalized to bracketed form (e.g., ::1 -> http://[::1]).
- Hostnames are resolved to ALL A/AAAA records and each address is evaluated.
- Private, loopback, link-local, multicast, and reserved IPs are blocked by default unless explicitly whitelisted by IP or CIDR.
- If a whitelist is provided, the destination must match it; otherwise it is denied even if not on the blacklist.
- IPv4 private addresses are also detected when supplied in hexadecimal, octal, or single-integer forms (e.g., `0x7f000001`, `0177.0.0.1`, `2130706433`).

## Express middleware

Use globally (entire app):

```js
const express = require('express')
const ssrf = require('ssrf')

const app = express()
app.use(express.json())

app.use(
  ssrf.middleware(
    {
      // Lists from files or arrays
      // blacklistFile: 'C:\\lists\\deny.txt',
      whitelistHosts: ['api.example.com'],
      whitelistCIDRs: ['2001:db8::/32', '203.0.113.0/24'],
      blacklistCIDRs: ['10.0.0.0/8', 'fc00::/7'],
      path: false
    },
    {
      source: 'body',        // 'body' | 'query' | 'params' | 'headers'
      key: 'url',            // field name in the chosen source
      attachKey: 'safeUrl',  // attach approved URL to req.safeUrl
      replaceOriginal: false,
      blockOnError: true,    // respond with 400 + JSON by default
      statusCode: 400,
      // onError: (errors, req, res, next) => { ...custom handler... }
    }
  )
)

app.post('/fetch', (req, res) => {
  res.json({ ok: true, safeUrl: req.safeUrl })
})
```

Use at endpoint level (route-specific config) with an isolated instance:

```js
const filesOnly = ssrf.create({
  whitelistHosts: ['files.example.com'],
  path: true
})

app.post('/upload', filesOnly.middleware({ source: 'query', key: 'target' }), (req, res) => {
  res.json({ ok: true, url: req.safeUrl })
})
```

Direct use with an isolated instance (no global state):

```js
const instance = ssrf.create({ path: false })
try {
  const safe = await instance.url('example.com')
  // use safe
} catch (e) {
  // e.message contains a JSON array of reasons
}
```

## Examples

- Full Express example: `examples/express-server/server.js`
  - App-level middleware: `app.use(ssrf.middleware(...))`
  - Route-level middleware with isolated instance: `const inst = ssrf.create(...); app.post('/path', inst.middleware(...))`

## TypeScript

This package ships type definitions. Import normally in TS projects and get intellisense for options and middleware:

```ts
import ssrf = require('ssrf')

const inst = ssrf.create({ path: false, whitelistCIDRs: ['2001:db8::/32'] })
const safe = await inst.url('example.com')
```
