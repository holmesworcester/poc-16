"""Fail-closed placeholder for the upload broker tracked by x1p.17.1."""
from workers import Response, WorkerEntrypoint


class Default(WorkerEntrypoint):
    async def fetch(self, _request):
        return Response(
            b'{"error":"upload broker is not implemented"}',
            status=503,
            headers={
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
            },
        )
