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

  // Forward all headers with preserved casing
  // Use setHeader() on request object to preserve exact casing
  const options = {
    method: req.method,
  };

  const proxyReq = https.request(targetUrl, options, (proxyRes) => {
    // Forward status and headers
    res.writeHead(proxyRes.statusCode, proxyRes.headers);

    // Pipe response
    proxyRes.pipe(res);
  });

  // Set headers manually to preserve exact casing (Node.js lowercases headers in options object)
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    const key = req.rawHeaders[i];
    const value = req.rawHeaders[i + 1];
    // Skip host header
    if (key.toLowerCase() !== 'host') {
      proxyReq.setHeader(key, value);
    }
  }

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

