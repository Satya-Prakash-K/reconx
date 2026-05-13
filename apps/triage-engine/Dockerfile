FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY libs/shared-python /tmp/shared-python
RUN pip install --no-cache-dir /tmp/shared-python && rm -rf /tmp/shared-python

COPY apps/triage-engine/pyproject.toml .
RUN pip install --no-cache-dir .

COPY apps/triage-engine/src ./src

EXPOSE 8003
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8003"]
