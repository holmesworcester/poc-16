"""Cloudflare scheduled entrypoint for Applier+Reader hosted storage."""
from workers import Response, WorkerEntrypoint

if __package__:
    from .applier_runtime import Settings, drain
else:
    from applier_runtime import Settings, drain


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        """Expose health only; HTTP callers receive no mutation authority."""
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

    async def scheduled(self, _controller, environment, _context):
        await drain(environment)
