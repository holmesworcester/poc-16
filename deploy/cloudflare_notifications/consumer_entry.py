"""Cloudflare Queue consumer entrypoint."""
from workers import WorkerEntrypoint

if __package__:
    from .consumer import consume
else:
    from consumer import consume


class Default(WorkerEntrypoint):
    async def queue(self, batch):
        await consume(self.env, batch)
