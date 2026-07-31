"""Cloudflare scheduled and private-wake scanner entrypoint."""
from workers import WorkerEntrypoint

if __package__:
    from .scanner import get_state_bounded, scan
else:
    from scanner import get_state_bounded, scan


class Default(WorkerEntrypoint):
    async def scheduled(self, controller, env, ctx):
        return await scan(self.env)

    async def wake(self):
        """Optional private service-binding wake; Cron remains the fallback."""
        return await scan(self.env)

    async def get_bounded(self, key, maximum):
        return await get_state_bounded(self.env, key, maximum)
