#!/usr/bin/env node
'use strict';

const http = require('http');
const url  = require('url');

const PORT = process.env.PORT || 9000;

function parseCookies(cookieHeader) {
  if (!cookieHeader) return {};
  return Object.fromEntries(
    cookieHeader.split(';').map(pair => {
      const idx = pair.indexOf('=');
      if (idx === -1) return [pair.trim(), ''];
      return [pair.slice(0, idx).trim(), pair.slice(idx + 1).trim()];
    })
  );
}

const server = http.createServer((req, res) => {
  const parsed  = url.parse(req.url, true);
  const cookies = parseCookies(req.headers['cookie']);

  // Accumulate body chunks
  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    const rawBody = Buffer.concat(chunks).toString();

    let body = rawBody;
    const ct = (req.headers['content-type'] || '').split(';')[0].trim();
    if (rawBody && (ct === 'application/json' || ct === 'text/json')) {
      try { body = JSON.parse(rawBody); } catch (_) { /* keep raw */ }
    }

    const info = {
      method:  req.method,
      path:    parsed.pathname,
      query:   parsed.query,
      headers: req.headers,
      cookies,
      body:    body || null,
    };

    console.log('─'.repeat(72));
    console.log(JSON.stringify(info, null, 2));

    const responseBody = JSON.stringify(info, null, 2);
    res.writeHead(200, {
      'Content-Type':   'application/json',
      'Content-Length': Buffer.byteLength(responseBody),
    });
    res.end(responseBody);
  });
});

server.listen(PORT, () => {
  console.log(`Local test backend listening on http://0.0.0.0:${PORT}`);
});
