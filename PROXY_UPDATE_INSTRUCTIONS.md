# Update Proxy Server on Linode

## ⚡ Automated Deployment (Recommended)

If you've set up automated deployment (see `PROXY_AUTOMATED_DEPLOYMENT.md`), updates happen automatically when you push to GitHub. No manual steps needed!

## Manual Update Options

### Option 0: Use Update Script (If Git Setup)

If you've set up git deployment:

```bash
ssh root@194.195.119.120
cd /opt/dgft-proxy
./scripts/update-proxy.sh
```

### Option 1: Copy-Paste via Linode Console (One-Time Manual Update)

1. Open Linode Console (Launch LISH Console in Linode dashboard)

2. Run these commands:

```bash
cd /opt/dgft-proxy
cat > proxy-server.js << 'EOF'
const http = require('http');
const https = require('https');
const { URL } = require('url');

const DGFT_BASE_URL = 'https://apiservices.dgft.gov.in';

const server = http.createServer((req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, accessToken, client_id, secretVal, messageID, x-api-key');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // Parse the target path from request URL
  const targetPath = req.url;
  const targetUrl = `${DGFT_BASE_URL}${targetPath}`;

  console.log(`[${new Date().toISOString()}] Proxying ${req.method} ${targetPath} -> ${targetUrl}`);

  // Reconstruct headers from rawHeaders to preserve exact casing
  // rawHeaders is an array: [key1, value1, key2, value2, ...]
  const headers = {};
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    const key = req.rawHeaders[i];
    const value = req.rawHeaders[i + 1];
    // Skip host header
    if (key.toLowerCase() !== 'host') {
      headers[key] = value;
    }
  }

  // Forward all headers with preserved casing
  const options = {
    method: req.method,
    headers: headers,
  };

  const proxyReq = https.request(targetUrl, options, (proxyRes) => {
    // Forward status and headers
    res.writeHead(proxyRes.statusCode, proxyRes.headers);

    // Pipe response
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    console.error(`Proxy error: ${err.message}`);
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end(`Proxy error: ${err.message}`);
  });

  // Pipe request body
  req.pipe(proxyReq);
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`DGFT Proxy Server running on port ${PORT}`);
  console.log(`Proxying requests to: ${DGFT_BASE_URL}`);
});
EOF

pm2 restart dgft-proxy
pm2 logs dgft-proxy --lines 20
```

3. Check the logs - you should see the proxy restart successfully.

## Option 2: Use SCP (if you have SSH access)

```bash
./deploy-proxy.sh 194.195.119.120 root
```

Or manually:
```bash
scp proxy-server.js root@194.195.119.120:/opt/dgft-proxy/proxy-server.js
ssh root@194.195.119.120 "cd /opt/dgft-proxy && pm2 restart dgft-proxy"
```

## Verify It's Working

After updating, test from your app - the 500 `AuthorizerConfigurationException` should be gone, and you should get either:
- A successful response, OR
- A different error (encryption/signature related, not authorizer)

