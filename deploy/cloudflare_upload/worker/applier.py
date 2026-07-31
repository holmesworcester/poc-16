"""Cloudflare private RPC entrypoint for one exact ingress pile."""
from workers import Response, WorkerEntrypoint
from deploy.repository_apply_wire import encode_apply_result

if __package__:
    from .applier_runtime import Settings, apply
else:
    from applier_runtime import Settings, apply


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        """Expose health only; public HTTP receives no mutation authority."""
        try:
            Settings.from_env(self.env)
        except Exception:
            return Response(
                b'{"ok":false}',
                status=503,
                headers={
                    "Cache-Control": "no-store",
                    "Content-Type": "application/json",
                },
            )
        method = request.method
        method = method.value if hasattr(method, "value") else str(method)
        path = str(request.url).split("?", 1)[0].rstrip("/")
        if method == "GET" and path.endswith("/healthz"):
            return Response(
                b'{"ok":true}',
                status=200,
                headers={
                    "Cache-Control": "no-store",
                    "Content-Type": "application/json",
                },
            )
        return Response(
            b"",
            status=405,
            headers={"Cache-Control": "no-store"},
        )

    async def apply(self, key, digest):
        """Provider-private service-binding RPC; bytes remain in R2."""
        return encode_apply_result(await apply(self.env, key, digest))
