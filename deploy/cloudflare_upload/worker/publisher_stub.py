"""Fail-closed placeholder for the store-only publisher tracked by x1p.17.2."""
from workers import Response, WorkerEntrypoint


class Default(WorkerEntrypoint):
    async def fetch(self, _request):
        return Response(
            b'{"error":"upload publisher is not implemented"}',
            status=503,
            headers={
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
            },
        )

    async def scheduled(self, _controller, _environment, _context):
        return None
