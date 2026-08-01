const MAX_REQUEST_BYTES = 16 * 1024;

function response(document, status) {
  return new Response(JSON.stringify(document), {
    status,
    headers: {"content-type": "application/json", "cache-control": "no-store"},
  });
}

async function boundedText(request, declared) {
  if (request.body === null) throw new Error("body");
  const reader = request.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const {done, value} = await reader.read();
    if (done) break;
    if (!(value instanceof Uint8Array)) throw new Error("body");
    length += value.byteLength;
    if (length > MAX_REQUEST_BYTES || length > declared) {
      await reader.cancel("request bound");
      throw new Error("body");
    }
    chunks.push(value);
  }
  if (length !== declared) throw new Error("body");
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", {fatal: true}).decode(body);
}

export default {
  async fetch(request, env) {
    const expected = `Bearer ${env.LAUNCH_HARNESS_SECRET}`;
    if (request.method !== "POST"
        || new URL(request.url).pathname !== "/v1/send"
        || request.headers.get("authorization") !== expected) {
      return response({status: "not-found"}, 404);
    }
    const declared = request.headers.get("content-length");
    if (declared === null) {
      return response({status: "length-required"}, 411);
    }
    if (!/^(0|[1-9]\d*)$/.test(declared)
        || Number(declared) > MAX_REQUEST_BYTES) {
      return response({status: "too-large"}, 413);
    }
    let body;
    try {
      body = await boundedText(request, Number(declared));
    } catch (_error) {
      return response({status: "too-large"}, 413);
    }
    let document;
    try {
      document = JSON.parse(body);
    } catch (_error) {
      return response({status: "invalid"}, 400);
    }
    const callerRelease = {
      enabled: true,
      format: "poc16-cloudflare-notification-runtime-v1",
      identity: env.POC16_DEPLOYMENT_IDENTITY,
      release_id: env.POC16_RELEASE_ID,
      role: "notification-consumer",
      software_digest: env.POC16_SOFTWARE_DIGEST,
    };
    const result = await env.FCM_BOUNDARY.send(document, callerRelease);
    const exact = result?.status === "accepted"
      && result.worker_version_id === env.POC16_EXPECTED_FCM_VERSION;
    return response(exact ? result : {status: "retry"}, exact ? 200 : 503);
  },
};
