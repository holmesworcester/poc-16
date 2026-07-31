"""Private Cloudflare service entrypoint for bounded canonical reads."""
from workers import WorkerEntrypoint

if __package__:
    from .reader import get_bounded, read_versioned
else:
    from reader import get_bounded, read_versioned


class Default(WorkerEntrypoint):
    async def get_bounded(self, key, maximum):
        return await get_bounded(self.env, key, maximum)

    async def read_versioned(self, key, maximum):
        return await read_versioned(self.env, key, maximum)
