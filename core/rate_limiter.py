import asyncio
import time
import os
import redis.asyncio as redis
from typing import Optional

# Get Redis URL from env
REDIS_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')

class RedisRateLimiter:
    """
    Distributed Rate Limiter using Redis.
    Implements a Token Bucket or Leaky Bucket algorithm.
    """
    def __init__(self, redis_url: str = None):
        self.redis_url = redis_url or REDIS_URL
        self._redis: Optional[redis.Redis] = None

    async def get_redis(self):
        if not self._redis:
            self._redis = redis.from_url(self.redis_url, encoding="utf-8", decode_responses=True)
        return self._redis

    async def acquire(self, key: str, limit: int, period: int = 1, block: bool = True):
        """
        Acquire a token.
        key: Identifier (e.g., 'rate_limit:TEST.COM')
        limit: Max actions per period
        period: Time window in seconds
        block: If True, wait until token is available.
        """
        r = await self.get_redis()
        
        # Simple Fixed Window for scan tasks (coarse grained)
        # For a more precise limiter (leaky bucket), we'd use Lua scripts.
        # Given we are limiting *tasks* (which last seconds/minutes), coarse is fine.
        
        while True:
            # Current window key
            ts = int(time.time() / period)
            window_key = f"rl:{key}:{ts}"
            
            # Atomic INCR
            current = await r.incr(window_key)
            
            if current == 1:
                await r.expire(window_key, period + 1)
            
            if current <= limit:
                return True
            
            if not block:
                return False
                
            # Wait a bit before retrying
            await asyncio.sleep(0.1)

    async def close(self):
        if self._redis:
            await self._redis.close()

# Global Instance
rate_limiter = RedisRateLimiter()
