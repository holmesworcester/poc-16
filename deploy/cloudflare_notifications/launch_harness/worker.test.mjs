import assert from "node:assert/strict";
import {test} from "node:test";

import worker from "./worker.mjs";

const EXPECTED_VERSION = "44444444-4444-4444-8444-444444444444";

function fixture() {
  return {
    FCM_BOUNDARY: {
      calls: [],
      workerVersion: EXPECTED_VERSION,
      async send(document, release) {
        this.calls.push({document, release});
        return {
          status: "accepted",
          message_id: "provider-message",
          worker_version_id: this.workerVersion,
        };
      },
    },
    LAUNCH_HARNESS_SECRET: "secret",
    POC16_DEPLOYMENT_IDENTITY: "a".repeat(64),
    POC16_EXPECTED_FCM_VERSION: EXPECTED_VERSION,
    POC16_RELEASE_ID: "b".repeat(64),
    POC16_SOFTWARE_DIGEST: "c".repeat(64),
  };
}

test("temporary harness authenticates and binds the exact FCM RPC", async () => {
  const env = fixture();
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

test("active FCM version switch during launch testing fails closed", async () => {
  const env = fixture();
  const body = JSON.stringify({format: "poc16-fcm-service-v1"});
  const request = () => new Request("https://harness.example/v1/send", {
    method: "POST",
    headers: {
      authorization: "Bearer secret",
      "content-length": String(new TextEncoder().encode(body).byteLength),
    },
    body,
  });

  assert.equal((await worker.fetch(request(), env)).status, 200);
  env.FCM_BOUNDARY.workerVersion =
    "55555555-5555-4555-8555-555555555555";
  const switched = await worker.fetch(request(), env);

  assert.equal(switched.status, 503);
  assert.deepEqual(await switched.json(), {status: "retry"});
  assert.equal(env.FCM_BOUNDARY.calls.length, 2);
});

test("temporary harness bounds request bytes before FCM", async () => {
  const env = fixture();
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
