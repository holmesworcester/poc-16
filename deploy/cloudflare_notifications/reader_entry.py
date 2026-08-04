"""Private Cloudflare service entrypoint for bounded canonical reads."""
from workers import WorkerEntrypoint

if __package__:
    from .reader import get_bounded, list_page, read_versioned, release_state
else:
    from reader import get_bounded, list_page, read_versioned, release_state


class Default(WorkerEntrypoint):
    async def get_bounded(self, key, maximum):
        return await get_bounded(self.env, key, maximum)

    async def read_versioned(self, key, maximum):
        return await read_versioned(self.env, key, maximum)

    async def list_page(self, prefix, cursor, limit):
        return await list_page(self.env, prefix, cursor, limit)

    async def release(self):
        return release_state(self.env)
