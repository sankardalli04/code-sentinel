import asyncio
import json
import uuid
import time
from typing import Dict, Any, Optional, Callable, Awaitable
from codesentinel.core.config import settings
from codesentinel.core.logger import logger

try:
    import redis.asyncio as aioredis
except ImportError:
    aioredis = None


class AuditJob:
    def __init__(self, job_id: str, payload: Dict[str, Any]):
        self.job_id = job_id
        self.payload = payload
        self.status = "PENDING"
        self.created_at = time.time()
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None


class BaseTaskQueue:
    async def enqueue(self, payload: Dict[str, Any]) -> str:
        raise NotImplementedError

    async def get_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    async def start_worker(self, handler: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]):
        raise NotImplementedError


class MemoryTaskQueue(BaseTaskQueue):
    """In-memory async queue for standalone and test environments."""

    def __init__(self):
        self._queue: asyncio.Queue = asyncio.Queue()
        self._jobs: Dict[str, AuditJob] = {}
        self._worker_task: Optional[asyncio.Task] = None

    async def enqueue(self, payload: Dict[str, Any]) -> str:
        job_id = str(uuid.uuid4())
        job = AuditJob(job_id, payload)
        self._jobs[job_id] = job
        await self._queue.put(job)
        logger.info(f"Enqueued job {job_id} to in-memory queue.")
        return job_id

    async def get_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        job = self._jobs.get(job_id)
        if not job:
            return None
        return {
            "job_id": job.job_id,
            "status": job.status,
            "created_at": job.created_at,
            "result": job.result,
            "error": job.error
        }

    async def start_worker(self, handler: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]):
        logger.info("Started in-memory background worker loop.")
        while True:
            job: AuditJob = await self._queue.get()
            job.status = "PROCESSING"
            logger.info(f"Worker processing job {job.job_id}...")
            try:
                res = await handler(job.payload)
                job.status = "COMPLETED"
                job.result = res
                logger.info(f"Job {job.job_id} completed successfully.")
            except Exception as e:
                job.status = "FAILED"
                job.error = str(e)
                logger.error(f"Job {job.job_id} failed: {e}")
            finally:
                self._queue.task_done()


class RedisTaskQueue(BaseTaskQueue):
    """Production Redis-backed task queue."""

    def __init__(self, redis_url: str = settings.REDIS_URL):
        self.redis_url = redis_url
        self.redis_client = None
        if aioredis:
            self.redis_client = aioredis.from_url(redis_url, decode_responses=True)

    async def enqueue(self, payload: Dict[str, Any]) -> str:
        if not self.redis_client:
            raise RuntimeError("Redis client not available.")
        job_id = str(uuid.uuid4())
        job_data = {
            "job_id": job_id,
            "status": "PENDING",
            "payload": json.dumps(payload),
            "created_at": time.time(),
        }
        await self.redis_client.hset(f"job:{job_id}", mapping=job_data)
        await self.redis_client.lpush("codesentinel:jobs", job_id)
        logger.info(f"Enqueued job {job_id} to Redis queue.")
        return job_id

    async def get_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        if not self.redis_client:
            return None
        data = await self.redis_client.hgetall(f"job:{job_id}")
        if not data:
            return None
        return {
            "job_id": job_id,
            "status": data.get("status"),
            "result": json.loads(data.get("result", "{}")) if data.get("result") else None,
            "error": data.get("error")
        }

    async def start_worker(self, handler: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]):
        if not self.redis_client:
            return
        logger.info("Started Redis worker loop.")
        while True:
            item = await self.redis_client.brpop("codesentinel:jobs", timeout=5)
            if not item:
                continue
            _, job_id = item
            job_key = f"job:{job_id}"
            await self.redis_client.hset(job_key, "status", "PROCESSING")
            raw_payload = await self.redis_client.hget(job_key, "payload")
            try:
                payload = json.loads(raw_payload) if raw_payload else {}
                result = await handler(payload)
                await self.redis_client.hset(job_key, mapping={
                    "status": "COMPLETED",
                    "result": json.dumps(result)
                })
            except Exception as e:
                await self.redis_client.hset(job_key, mapping={
                    "status": "FAILED",
                    "error": str(e)
                })


def get_task_queue() -> BaseTaskQueue:
    """Factory returning configured task queue."""
    if settings.QUEUE_DRIVER == "redis" and aioredis:
        try:
            return RedisTaskQueue()
        except Exception:
            logger.warning("Failed to connect to Redis. Falling back to MemoryTaskQueue.")
    return MemoryTaskQueue()


task_queue = get_task_queue()
