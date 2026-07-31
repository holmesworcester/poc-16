import assert from "node:assert/strict";
import {test} from "node:test";

import worker from "./worker.mjs";

const env = {
  FCM_BOUNDARY: {
    calls: [],
    async send(document, release) {
      this.calls.push({document, release});
      return {status: "accepted", message_id: "provider-message"};
    },
  },
  LAUNCH_HARNESS_SECRET: "secret",
  POC16_DEPLOYMENT_IDENTITY: "a".repeat(64),
  POC16_RELEASE_ID: "b".repeat(64),
  POC16_SOFTWARE_DIGEST: "c".repeat(64),
};

test("temporary harness authenticates and binds the exact FCM RPC", async () => {
  const unauthorized = await worker.fetch(new Request(
    "https://harness.example/v1/send", {method: "POST", body: "{}"}), env);
  assert.equal(unauthorized.status, 404);
  assert.equal(env.FCM_BOUNDARY.calls.length, 0);

  const document = {format: "poc16-fcm-service-v1"};
  const body = JSON.stringify(document);
  const accepted = await worker.fetch(new Request(
    "https://harness.example/v1/send", {
      method: "POST",
      headers: {
        authorization: "Bearer secret",
        "content-length": String(new TextEncoder().encode(body).byteLength),
      },
      body,
    }), env);

  assert.equal(accepted.status, 200);
  assert.deepEqual(env.FCM_BOUNDARY.calls, [{
    document,
    release: {
      enabled: true,
      format: "poc16-cloudflare-notification-runtime-v1",
      identity: "a".repeat(64),
      release_id: "b".repeat(64),
      role: "notification-consumer",
      software_digest: "c".repeat(64),
    },
  }]);
});

test("temporary harness bounds request bytes before FCM", async () => {
  const before = env.FCM_BOUNDARY.calls.length;
  const response = await worker.fetch(new Request(
    "https://harness.example/v1/send", {
      method: "POST",
      headers: {
        authorization: "Bearer secret",
        "content-length": String(16 * 1024 + 1),
      },
      body: "{}",
    }), env);
  assert.equal(response.status, 413);
  assert.equal(env.FCM_BOUNDARY.calls.length, before);

  const absent = await worker.fetch(new Request(
    "https://harness.example/v1/send", {
      method: "POST",
      headers: {authorization: "Bearer secret"},
      body: "{}",
    }), env);
  assert.equal(absent.status, 411);
  assert.equal(env.FCM_BOUNDARY.calls.length, before);

  const underreported = await worker.fetch(new Request(
    "https://harness.example/v1/send", {
      method: "POST",
      headers: {
        authorization: "Bearer secret",
        "content-length": "2",
      },
      body: "x".repeat(16 * 1024),
    }), env);
  assert.equal(underreported.status, 413);
  assert.equal(env.FCM_BOUNDARY.calls.length, before);
});
