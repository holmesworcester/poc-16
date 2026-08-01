import {WorkerEntrypoint} from "cloudflare:workers";
import {FcmBridge, releaseFor, sendFromWorkerVersion} from "./core.mjs";

export default class NotificationFcmBoundary extends WorkerEntrypoint {
  async send(document, callerRelease) {
    this.bridge ??= new FcmBridge(this.env);
    return await sendFromWorkerVersion(
      this.env, this.bridge, document, callerRelease);
  }

  async release() {
    return releaseFor(this.env);
  }
}
