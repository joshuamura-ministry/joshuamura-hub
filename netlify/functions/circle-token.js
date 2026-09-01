/* ============================================================
   circle-token  —  the Watchman at the door of the circles
   ------------------------------------------------------------
   Signs a JaaS (Jitsi-as-a-Service) JWT so the live circles are
   PRIVATE and have NO 5-minute limit.

   The app calls:   /.netlify/functions/circle-token?room=X&name=Y&pass=Z
   It answers:      { ok:true, token:"...", moderator:true|false }

   Environment variables (set in Netlify → Site settings → Environment):
     JAAS_APP_ID    vpaas-magic-cookie-86d8e477e0754382b3deab81b3e8dcfb
     JAAS_KID       vpaas-magic-cookie-86d8e477e0754382b3deab81b3e8dcfb/780697
     JAAS_KEY       the ENTIRE contents of the .pk file
                    (-----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----)
     MOD_PASS       the moderator passphrase Pastor Josh types
                    (optional; defaults to shepherd2026)

   The private key lives ONLY here, in Netlify's encrypted store.
   It is never in the repo, never in the HTML, never in the browser.
   ============================================================ */

const crypto = require('crypto');

/* ---- base64url helpers (no padding, URL-safe) ---- */
function b64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}
function b64urlFromBuffer(buf) {
  return buf
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/* ---- sign a JWT with RS256 ---- */
function signJwt(payload, privateKey, kid) {
  const header = { alg: 'RS256', typ: 'JWT', kid: kid };
  const encHeader = b64url(JSON.stringify(header));
  const encPayload = b64url(JSON.stringify(payload));
  const signingInput = encHeader + '.' + encPayload;

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign(privateKey);

  return signingInput + '.' + b64urlFromBuffer(signature);
}

exports.handler = async function (event) {
  const headers = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store'
  };

  try {
    const APP_ID = process.env.JAAS_APP_ID;
    const KID = process.env.JAAS_KID;
    let KEY = process.env.JAAS_KEY;
    const MOD_PASS = process.env.MOD_PASS || 'shepherd2026';

    /* If the vault isn't stocked yet, say so plainly.
       The app already falls back to the public room, so nothing breaks. */
    if (!APP_ID || !KID || !KEY) {
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          ok: false,
          reason: 'missing-env',
          need: ['JAAS_APP_ID', 'JAAS_KID', 'JAAS_KEY'].filter(function (k) {
            return !process.env[k];
          })
        })
      };
    }

    /* Netlify's UI turns real newlines into \n escapes. Put them back. */
    KEY = KEY.replace(/\\n/g, '\n').trim();

    const q = event.queryStringParameters || {};
    const room = (q.room || '').trim();
    const name = (q.name || 'Friend').trim().slice(0, 60);
    const pass = q.pass || '';

    if (!room) {
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ ok: false, reason: 'no-room' })
      };
    }

    /* ---- Only OUR rooms get a token. ----------------------------------------
       Without this, anyone who worked out that rooms are made by editing the
       address could open #meet-whatever and hold their own meetings on this
       JaaS account — spending the 25-unique-people monthly allowance that the
       prayer circle and the classes depend on.
       The fixed rooms are named. Upper Room meetings are allowed only in the
       shape the panel actually produces: a word, optionally followed by a
       six-character tail. Anything else is refused. */
    const FIXED = [
      'JoshuaMuraPrayer',      /* the Altar */
      'JoshuaMuraTeaching',    /* the Live Class */
      'JoshuaMuraExpedition'   /* the Watchfire */
    ];
    /* An Upper Room name is <base>-<tail>, where the tail is derived from the
       base with the private key. Only this function can produce a valid tail,
       so a room name invented in the address bar simply will not verify. */
    function meetTail(base){
      return crypto.createHmac('sha256', KEY)
                   .update('room:' + base.toLowerCase())
                   .digest('base64')
                   .replace(/[^a-z0-9]/gi, '')
                   .toLowerCase()
                   .slice(0, 8);
    }
    function meetOK(r){
      const m = String(r).match(/^([A-Za-z][A-Za-z0-9-]{0,30})-([a-z0-9]{8})$/);
      if (!m) return false;
      const want = meetTail(m[1]);
      /* constant-time-ish compare */
      if (want.length !== m[2].length) return false;
      let diff = 0;
      for (let i = 0; i < want.length; i++) diff |= want.charCodeAt(i) ^ m[2].charCodeAt(i);
      return diff === 0;
    }

    /* Minting: the panel asks for a room name and must prove it is Pastor Josh
       by sending the moderator passphrase. Nobody else can mint. */
    if ((q.mint || '') === '1') {
      if (pass !== MOD_PASS || !MOD_PASS) {
        return { statusCode: 200, headers,
                 body: JSON.stringify({ ok: false, reason: 'not-authorised' }) };
      }
      const base = (q.base || 'planning').trim()
                     .replace(/\s+/g, '-').replace(/[^A-Za-z0-9-]/g, '')
                     .replace(/-[a-z0-9]{8}$/, '').slice(0, 24) || 'planning';
      const stamp = Math.random().toString(36).slice(2, 6);
      const full  = base + stamp;
      return { statusCode: 200, headers,
               body: JSON.stringify({ ok: true, room: full + '-' + meetTail(full) }) };
    }

    const allowed = FIXED.indexOf(room) >= 0 || meetOK(room);

    if (!allowed) {
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ ok: false, reason: 'room-not-allowed' })
      };
    }

    /* Moderator only if the passphrase matches exactly. */
    const isMod = pass !== '' && pass === MOD_PASS;

    const now = Math.floor(Date.now() / 1000);
    const payload = {
      aud: 'jitsi',
      iss: 'chat',
      sub: APP_ID,
      room: room,
      exp: now + 60 * 60 * 6,   /* good for 6 hours — a long meeting is fine */
      nbf: now - 30,            /* small clock-skew cushion */
      context: {
        user: {
          name: name,
          moderator: isMod ? 'true' : 'false'
        },
        features: {
          livestreaming: isMod ? 'true' : 'false',
          recording: isMod ? 'true' : 'false',
          transcription: 'false',
          'outbound-call': 'false'
        }
      }
    };

    const token = signJwt(payload, KEY, KID);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ ok: true, token: token, moderator: isMod })
    };
  } catch (err) {
    /* Never throw at the visitor. The app keeps the public room. */
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ ok: false, reason: 'sign-failed', detail: String(err && err.message || err) })
    };
  }
};
