import os
import json
import asyncio
import redis.asyncio as redis

# Use the same Redis URL as Celery
REDIS_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')

class EventBus:
    def __init__(self):
        self.redis = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
        self.pubsub = None

    async def publish(self, channel: str, message: dict):
        """Publish a message to a specific channel."""
        # Redis connection might be closed if not managed well in sync contexts
        # Usually for fire-and-forget in sync code (Celery tasks), we might need a sync wrapper or separate connection
        await self.redis.publish(channel, json.dumps(message))

    async def subscribe(self, channel: str):
        """Subscribe to a channel and return the pubsub object."""
        self.pubsub = self.redis.pubsub()
        await self.pubsub.subscribe(channel)
        return self.pubsub

    async def listen(self):
        """Generator to yield messages from subscribed channels."""
        if not self.pubsub:
            raise Exception("No active subscription. Call subscribe() first.")
        
        async for message in self.pubsub.listen():
            if message['type'] == 'message':
                yield json.loads(message['data'])

    async def close(self):
        if self.pubsub:
            await self.pubsub.unsubscribe()
        await self.redis.close()

# Global Event Bus Instance
event_bus = EventBus()
