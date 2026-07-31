import {WorkerEntrypoint} from "cloudflare:workers";
import {FcmBridge} from "./core.mjs";

export default class NotificationFcmBoundary extends WorkerEntrypoint {
  async send(document) {
    this.bridge ??= new FcmBridge(this.env);
    return await this.bridge.send(document);
  }
}
