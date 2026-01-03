import os
from celery import Celery

# Get env vars
BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')

celery_app = Celery(
    'recon_tasks',
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
    include=['core.tasks']  # We will define tasks in core/tasks.py
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    # Optimize for 12-thread CPU
    worker_concurrency=10, 
    worker_prefetch_multiplier=1, # Fair dispatch
    broker_connection_retry_on_startup=True
)
