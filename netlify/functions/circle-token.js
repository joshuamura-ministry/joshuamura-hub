// circle-token.js — JaaS (8x8) JWT signer for Joshua Mura's live circles
// Zero npm dependencies: uses Node's built-in crypto only.

const crypto = require('crypto');

function b64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function normalizeKey(raw) {
  if (!raw) return raw;
  let k = raw.trim();
  if ((k.startsWith('"') && k.endsWith('"')) || (k.startsWith("'") && k.endsWith("'"))) {
    k = k.slice(1, -1);
  }
  k = k.replace(/\\r\\n/g, '\n').replace(/\\n/g, '\n').replace(/\r\n/g, '\n');
  return k;
}

function sign(payloadObj, privateKeyPem, kid) {
  const header = { alg: 'RS256', kid, typ: 'JWT' };
  const encHeader = b64url(JSON.stringify(header));
  const encPayload = b64url(JSON.stringify(payloadObj));
  const signingInput = encHeader + '.' + encPayload;

  let keyObject;
  const isPkcs1 = /BEGIN RSA PRIVATE KEY/.test(privateKeyPem);
  try {
    keyObject = crypto.createPrivateKey({
      key: privateKeyPem,
      format: 'pem',
      type: isPkcs1 ? 'pkcs1' : 'pkcs8',
    });
  } catch (e1) {
    keyObject = crypto.createPrivateKey(privateKeyPem);
  }

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  const signature = signer
    .sign(keyObject)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return signingInput + '.' + signature;
}

exports.handler = async (event) => {
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Cache-Control': 'no-store',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers, body: '' };
  }

  const APP_ID = process.env.JAAS_APP_ID;
  const KID = process.env.JAAS_KID;
  const PRIVATE_KEY = process.env.JAAS_PRIVATE_KEY;
  const MOD_PASS = process.env.CIRCLE_MOD_PASS;

  if (!APP_ID || !KID || !PRIVATE_KEY) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        ok: false,
        error:
          'Signer not configured: check JAAS_APP_ID, JAAS_KID, and JAAS_PRIVATE_KEY in Netlify environment variables.',
      }),
    };
  }

  let params = {};
  if (event.httpMethod === 'POST' && event.body) {
    try {
      params = JSON.parse(event.body);
    } catch (e) {
      params = {};
    }
  } else {
    params = event.queryStringParameters || {};
  }

  const room = (params.room || '').trim();
  const name = (params.name || 'Friend').toString().slice(0, 60);
  const pass = (params.pass || '').toString();

  // Safe diagnostic mode: ?diag=1 reports characteristics of the stored key
  // WITHOUT ever revealing the key itself. Helps debug parse failures.
  if (params.diag === '1') {
    const k = normalizeKey(PRIVATE_KEY);
    const firstLine = (k.split('\n')[0] || '').slice(0, 40);
    const lastLine = (k.trim().split('\n').pop() || '').slice(0, 40);
    const hasSmartQuotes = /[\u2018\u2019\u201C\u201D]/.test(k);
    const hasCRLF = /\r/.test(PRIVATE_KEY);
    const hasLiteralBackslashN = /\\n/.test(PRIVATE_KEY);
    const nonAscii = (k.match(/[^\x00-\x7F]/g) || []).length;
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        ok: true,
        diag: {
          rawLength: PRIVATE_KEY.length,
          normalizedLength: k.length,
          firstLine,
          lastLine,
          lineCount: k.split('\n').length,
          startsWithBegin: k.startsWith('-----BEGIN'),
          endsWithEnd: k.trim().endsWith('KEY-----'),
          hasSmartQuotes,
          hasCRLF,
          hasLiteralBackslashN,
          nonAsciiCharCount: nonAscii,
        },
      }),
    };
  }

  if (!room) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ ok: false, error: 'Missing room name.' }),
    };
  }

  const isModerator = MOD_PASS ? pass === MOD_PASS : false;

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    aud: 'jitsi',
    iss: 'chat',
    sub: APP_ID,
    room: room,
    iat: now,
    nbf: now - 5,
    exp: now + 60 * 60 * 4,
    context: {
      user: {
        id: 'josh-' + now,
        name: name,
        moderator: isModerator ? 'true' : 'false',
      },
      features: {
        livestreaming: 'false',
        recording: 'false',
        transcription: 'false',
        'outbound-call': 'false',
      },
    },
  };

  let token;
  try {
    token = sign(payload, normalizeKey(PRIVATE_KEY), KID);
  } catch (e) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        ok: false,
        error:
          'Could not sign token — the private key may be malformed. Re-paste the full PEM block (including BEGIN/END lines) into JAAS_PRIVATE_KEY.',
        detail: (e && e.message) ? e.message : String(e),
      }),
    };
  }

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      ok: true,
      token: token,
      moderator: isModerator,
      room: room,
    }),
  };
};
