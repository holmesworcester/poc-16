"""Cloudflare Python Worker entrypoint for the metadata-only upload broker."""
from workers import Response, WorkerEntrypoint

if __package__:
    from .runtime import handle
else:
    from runtime import handle


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        result = await handle(request, self.env)
        return Response(
            result.body,
            status=result.status,
            headers=result.headers,
        )
