/* Example Express server using ssrf middleware */

const express = require('express')
const ssrf = require('../../lib/index') // use 'ssrf' when installed from npm

const app = express()
app.use(express.json())

// App-level enforcement
app.use(
  ssrf.middleware(
    {
      // Example lists
      // blacklistFile: 'C\\lists\\deny.txt',
      whitelistHosts: ['api.example.com'],
      whitelistCIDRs: ['203.0.113.0/24', '2001:db8::/32'],
      blacklistCIDRs: ['10.0.0.0/8', 'fc00::/7'],
      path: false
    },
    {
      source: 'query',
      key: 'url',
      attachKey: 'safeUrl',
      blockOnError: true,
      statusCode: 400
    }
  )
)

// Simple endpoint: validate and return the safe URL
app.get('/check', (req, res) => {
  res.json({ ok: true, safeUrl: req.safeUrl })
})

// Route-level with isolated instance
const uploads = ssrf.create({
  whitelistHosts: ['files.example.com'],
  path: true
})

app.post('/upload', uploads.middleware({ source: 'body', key: 'target' }), (req, res) => {
  res.json({ ok: true, target: req.safeUrl })
})

const port = process.env.PORT || 3000
app.listen(port, () => {
  console.log(`Example SSRF server running on http://localhost:${port}`)
})
