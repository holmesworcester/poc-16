const FORMAT = "poc16-fcm-service-v1";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const FCM_SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
const MAX_RESPONSE_BYTES = 32 * 1024;
const MAX_PAYLOAD_BYTES = 1024;
const MAX_TARGET_BYTES = 4048;
const MAX_TTL_SECONDS = 28 * 24 * 60 * 60;
const FID = /^[0-9a-f]{64}$/;
const APPLICATION = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const ENVIRONMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function retry() {
  return {status: "retry"};
}

function bytesToBase64Url(value) {
  let binary = "";
  for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function textToBase64Url(value) {
  return bytesToBase64Url(new TextEncoder().encode(value));
}

function pemBytes(value) {
  if (typeof value !== "string" || value.length > 32 * 1024) throw new Error("private key");
  const body = value
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s/g, "");
  if (!body || !/^[A-Za-z0-9+/]+={0,2}$/.test(body)) throw new Error("private key");
  const binary = atob(body);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function parseServiceAccount(raw) {
  if (typeof raw !== "string" || !raw || raw.length > 64 * 1024) throw new Error("service account");
  const value = JSON.parse(raw);
  if (value === null || typeof value !== "object" || Array.isArray(value)
      || typeof value.project_id !== "string" || !value.project_id
      || value.project_id.length > 256
      || typeof value.client_email !== "string" || !value.client_email
      || value.client_email.length > 512
      || typeof value.private_key !== "string") {
    throw new Error("service account");
  }
  pemBytes(value.private_key);
  return {
    projectId: value.project_id,
    clientEmail: value.client_email,
    privateKey: value.private_key,
  };
}

function isAscii(value, maximum) {
  return typeof value === "string" && value.length > 0 && value.length <= maximum
    && /^[\x21-\x7e]+$/.test(value);
}

function canonicalBase64(value) {
  if (typeof value !== "string" || !value || value.length > 4 * Math.ceil(MAX_PAYLOAD_BYTES / 3)) {
    return false;
  }
  try {
    const decoded = atob(value);
    return decoded.length > 0 && decoded.length <= MAX_PAYLOAD_BYTES
      && btoa(decoded) === value;
  } catch (_error) {
    return false;
  }
}

function messageFor(document, application, environment) {
  if (document === null || typeof document !== "object" || Array.isArray(document)
      || document.format !== FORMAT
      || document.application !== application || !APPLICATION.test(document.application)
      || document.environment !== environment || !ENVIRONMENT.test(document.environment)
      || !["android", "apple"].includes(document.platform)
      || !isAscii(document.fid, MAX_TARGET_BYTES)
      || !FID.test(document.delivery_id)
      || !canonicalBase64(document.payload)
      || !Number.isSafeInteger(document.expires_at_ms) || document.expires_at_ms <= 0
      || !Number.isInteger(document.ttl_seconds) || document.ttl_seconds < 0
      || document.ttl_seconds > MAX_TTL_SECONDS
      || !["mention", "message"].includes(document.kind)) {
    throw new Error("push document");
  }
  const [title, body] = document.kind === "mention"
    ? ["You were mentioned", "Open the app to view the message"]
    : ["New message", "Open the app to view it"];
  return {
    fid: document.fid,
    data: {delivery_id: document.delivery_id, poc16: document.payload},
    notification: {title, body},
    android: {
      collapse_key: document.delivery_id,
      ttl: `${document.ttl_seconds}s`,
      priority: "NORMAL",
    },
    apns: {headers: {
      "apns-collapse-id": document.delivery_id,
      "apns-expiration": String(Math.floor(document.expires_at_ms / 1000)),
    }},
  };
}

async function boundedJson(response, maximum = MAX_RESPONSE_BYTES) {
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximum)) {
    throw new Error("provider response bound");
  }
  if (response.body === null) throw new Error("provider response body");
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const {done, value} = await reader.read();
    if (done) break;
    if (!(value instanceof Uint8Array)) throw new Error("provider response body");
    length += value.byteLength;
    if (length > maximum) {
      await reader.cancel("response bound");
      throw new Error("provider response bound");
    }
    chunks.push(value);
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(body));
}

function exactUnregistered(document) {
  const details = document?.error?.details;
  return Array.isArray(details) && details.some(detail =>
    detail !== null && typeof detail === "object"
    && detail["@type"] === "type.googleapis.com/google.firebase.fcm.v1.FcmError"
    && detail.errorCode === "UNREGISTERED");
}

class FcmBridge {
  constructor(env, options = {}) {
    this.env = env;
    this.fetch = options.fetch ?? globalThis.fetch;
    this.crypto = options.crypto ?? globalThis.crypto;
    this.now = options.now ?? (() => Date.now());
    this.account = null;
    this.accessToken = null;
    this.accessTokenExpiresAt = 0;
    this.tokenFlight = null;
  }

  settings() {
    if (this.env.POC16_DEPLOYMENT_ROLE !== "notification-fcm-boundary"
        || typeof this.env.FCM_APPLICATION !== "string"
        || !APPLICATION.test(this.env.FCM_APPLICATION)
        || typeof this.env.FCM_ENVIRONMENT !== "string"
        || !ENVIRONMENT.test(this.env.FCM_ENVIRONMENT)) {
      throw new Error("FCM boundary bindings");
    }
    if (this.account === null) {
      this.account = parseServiceAccount(this.env.FIREBASE_SERVICE_ACCOUNT_JSON);
    }
    return this.account;
  }

  async mintToken() {
    const account = this.settings();
    const issuedAt = Math.floor(this.now() / 1000);
    const header = textToBase64Url(JSON.stringify({alg: "RS256", typ: "JWT"}));
    const claims = textToBase64Url(JSON.stringify({
      iss: account.clientEmail,
      scope: FCM_SCOPE,
      aud: TOKEN_URL,
      iat: issuedAt,
      exp: issuedAt + 3600,
    }));
    const unsigned = `${header}.${claims}`;
    const key = await this.crypto.subtle.importKey(
      "pkcs8", pemBytes(account.privateKey),
      {name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"}, false, ["sign"]);
    const signature = await this.crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned));
    const response = await this.fetch(TOKEN_URL, {
      method: "POST",
      headers: {"content-type": "application/x-www-form-urlencoded"},
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: `${unsigned}.${bytesToBase64Url(signature)}`,
      }).toString(),
    });
    const result = await boundedJson(response);
    if (!response.ok || typeof result.access_token !== "string" || !result.access_token
        || !Number.isFinite(result.expires_in) || result.expires_in <= 60) {
      throw new Error("OAuth token response");
    }
    this.accessToken = result.access_token;
    this.accessTokenExpiresAt = this.now() + (result.expires_in - 60) * 1000;
    return this.accessToken;
  }

  async token() {
    if (this.accessToken !== null && this.now() < this.accessTokenExpiresAt) {
      return this.accessToken;
    }
    if (this.tokenFlight === null) {
      this.tokenFlight = this.mintToken().finally(() => { this.tokenFlight = null; });
    }
    return await this.tokenFlight;
  }

  async send(document) {
    try {
      const account = this.settings();
      const message = messageFor(
        document, this.env.FCM_APPLICATION, this.env.FCM_ENVIRONMENT);
      const accessToken = await this.token();
      const response = await this.fetch(
        `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(account.projectId)}/messages:send`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${accessToken}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({message}),
        });
      const result = await boundedJson(response);
      if (response.ok && typeof result.name === "string" && result.name
          && result.name.length <= 4096) {
        return {status: "accepted", message_id: result.name};
      }
      if (exactUnregistered(result)) return {status: "unregistered"};
      if ([401, 403].includes(response.status)) {
        this.accessToken = null;
        this.accessTokenExpiresAt = 0;
      }
      // INVALID_ARGUMENT may describe our payload, project, package, TTL, or
      // target.  It is never terminal here.  Only the typed FCM detail above
      // proves this exact FID is unregistered.
      return retry();
    } catch (_error) {
      return retry();
    }
  }
}

export {
  FcmBridge,
  FORMAT,
  MAX_RESPONSE_BYTES,
  boundedJson,
  exactUnregistered,
  messageFor,
  parseServiceAccount,
};
