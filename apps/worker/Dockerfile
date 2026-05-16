FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY libs/shared-python /tmp/shared-python
RUN pip install --default-timeout=1000 --no-cache-dir /tmp/shared-python && rm -rf /tmp/shared-python

COPY apps/worker/pyproject.toml .
RUN pip install --default-timeout=1000 --no-cache-dir .

COPY apps/worker/src ./src

CMD ["python", "-m", "celery", "-A", "src.tasks", "worker", "--loglevel=info", "--concurrency=4"]
