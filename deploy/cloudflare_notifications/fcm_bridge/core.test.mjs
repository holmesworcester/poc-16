import assert from "node:assert/strict";
import {test} from "node:test";
import {webcrypto} from "node:crypto";

import {
  FcmBridge,
  MAX_RESPONSE_BYTES,
  boundedJson,
  messageFor,
} from "./core.mjs";

function base64UrlBytes(value) {
  return Buffer.from(value.replaceAll("-", "+").replaceAll("_", "/"), "base64");
}

async function fixture() {
  const keys = await webcrypto.subtle.generateKey(
    {name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256"},
    true, ["sign", "verify"]);
  const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey("pkcs8", keys.privateKey));
  const privateKey = [
    "-----BEGIN PRIVATE KEY-----",
    ...pkcs8.toString("base64").match(/.{1,64}/g),
    "-----END PRIVATE KEY-----",
  ].join("\n");
  return {
    keys,
    env: {
      POC16_DEPLOYMENT_ROLE: "notification-fcm-boundary",
      POC16_DEPLOYMENT_OWNER: "unit-test-owner",
      FCM_APPLICATION: "poc16.mobile",
      FCM_ENVIRONMENT: "production",
      FIREBASE_SERVICE_ACCOUNT_JSON: JSON.stringify({
        project_id: "firebase-project",
        client_email: "worker@firebase-project.iam.gserviceaccount.com",
        private_key: privateKey,
      }),
    },
  };
}

function document() {
  return {
    application: "poc16.mobile",
    delivery_id: "d".repeat(64),
    environment: "production",
    expires_at_ms: 1_900_000_123_456,
    fid: "installation-fid",
    format: "poc16-fcm-service-v1",
    kind: "mention",
    payload: btoa("payload"),
    platform: "apple",
    ttl_seconds: 60,
  };
}

function jsonResponse(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {"content-type": "application/json", ...headers},
  });
}

test("bridge signs OAuth assertion and sends the current FID payload", async () => {
  const {env, keys} = await fixture();
  const calls = [];
  const fetch = async (url, options) => {
    calls.push({url, options});
    return calls.length === 1
      ? jsonResponse({access_token: "access-token", expires_in: 3600})
      : jsonResponse({name: "projects/firebase-project/messages/accepted"});
  };
  const bridge = new FcmBridge(env, {
    fetch, crypto: webcrypto, now: () => 1_800_000_000_000,
  });

  const result = await bridge.send(document());
  const repeated = await bridge.send(document());

  assert.deepEqual(result, {
    status: "accepted",
    message_id: "projects/firebase-project/messages/accepted",
  });
  assert.equal(repeated.status, "accepted");
  assert.equal(calls.filter(call => call.url.includes("oauth2")).length, 1);
  const assertion = new URLSearchParams(calls[0].options.body).get("assertion");
  const [header, claims, signature] = assertion.split(".");
  assert.deepEqual(JSON.parse(base64UrlBytes(header)), {alg: "RS256", typ: "JWT"});
  assert.deepEqual(JSON.parse(base64UrlBytes(claims)), {
    iss: "worker@firebase-project.iam.gserviceaccount.com",
    scope: "https://www.googleapis.com/auth/firebase.messaging",
    aud: "https://oauth2.googleapis.com/token",
    iat: 1800000000,
    exp: 1800003600,
  });
  assert.equal(await webcrypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", keys.publicKey, base64UrlBytes(signature),
    new TextEncoder().encode(`${header}.${claims}`)), true);

  const sent = JSON.parse(calls[1].options.body).message;
  assert.equal(sent.fid, "installation-fid");
  assert.equal("token" in sent, false);
  assert.deepEqual(sent.data, {
    delivery_id: "d".repeat(64), poc16: btoa("payload"),
  });
  assert.equal(sent.android.collapse_key, "d".repeat(64));
  assert.equal(sent.android.ttl, "60s");
  assert.equal(sent.apns.headers["apns-collapse-id"], "d".repeat(64));
  assert.equal(sent.apns.headers["apns-expiration"], "1900000123");
});

test("only exact typed FCM UNREGISTERED is terminal", async () => {
  const {env} = await fixture();
  const providerResponses = [
    jsonResponse({access_token: "access-token", expires_in: 3600}),
    jsonResponse({error: {
      status: "NOT_FOUND",
      details: [{
        "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
        errorCode: "UNREGISTERED",
      }],
    }}, 404),
    jsonResponse({error: {
      status: "INVALID_ARGUMENT",
      details: [{
        "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
        errorCode: "INVALID_ARGUMENT",
      }],
    }}, 400),
    jsonResponse({error: {status: "NOT_FOUND"}}, 404),
  ];
  const bridge = new FcmBridge(env, {
    crypto: webcrypto,
    fetch: async () => providerResponses.shift(),
  });

  assert.deepEqual(await bridge.send(document()), {status: "unregistered"});
  assert.deepEqual(await bridge.send(document()), {status: "retry"});
  assert.deepEqual(await bridge.send(document()), {status: "retry"});
});

test("configuration and document failures are retryable without provider calls", async () => {
  const {env} = await fixture();
  let calls = 0;
  const bridge = new FcmBridge(env, {
    crypto: webcrypto,
    fetch: async () => { calls += 1; throw new Error("not reached"); },
  });
  const wrongApplication = {...document(), application: "another.app"};

  assert.deepEqual(await bridge.send(wrongApplication), {status: "retry"});
  assert.equal(calls, 0);
  env.FIREBASE_SERVICE_ACCOUNT_JSON = "not json";
  assert.deepEqual(await new FcmBridge(env, {
    crypto: webcrypto, fetch: async () => { calls += 1; },
  }).send(document()), {status: "retry"});
  assert.equal(calls, 0);
});

test("provider JSON is bounded with and without Content-Length", async () => {
  await assert.rejects(
    boundedJson(jsonResponse({}, 200, {
      "content-length": String(MAX_RESPONSE_BYTES + 1),
    })), /bound/);
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(MAX_RESPONSE_BYTES));
      controller.enqueue(new Uint8Array([0]));
      controller.close();
    },
  });
  await assert.rejects(
    boundedJson(new Response(stream, {status: 200})), /bound/);
});

test("one raw KiB fits the encoded FCM data map and one byte more fails", () => {
  const exact = {...document(), payload: btoa("x".repeat(1024))};
  const message = messageFor(exact, "poc16.mobile", "production");

  assert.ok(new TextEncoder().encode(JSON.stringify(message.data)).byteLength < 4096);
  assert.throws(
    () => messageFor(
      {...exact, payload: btoa("x".repeat(1025))},
      "poc16.mobile", "production"),
    /push document/);
});
