import {WorkerEntrypoint} from "cloudflare:workers";
import {acceptsConsumerRelease, FcmBridge, releaseFor} from "./core.mjs";

export default class NotificationFcmBoundary extends WorkerEntrypoint {
  async send(document, callerRelease) {
    if (!acceptsConsumerRelease(this.env, callerRelease)) {
      return {status: "retry"};
    }
    this.bridge ??= new FcmBridge(this.env);
    return await this.bridge.send(document);
  }

  async release() {
    return releaseFor(this.env);
  }
}
