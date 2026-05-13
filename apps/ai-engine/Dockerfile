FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY libs/shared-python /tmp/shared-python
RUN pip install --no-cache-dir /tmp/shared-python && rm -rf /tmp/shared-python

COPY apps/ai-engine/pyproject.toml .
RUN pip install --no-cache-dir .

COPY apps/ai-engine/src ./src

CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8001"]
