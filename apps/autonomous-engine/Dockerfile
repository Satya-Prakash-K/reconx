FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential libffi-dev chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*

RUN pip install playwright && playwright install chromium --with-deps

COPY libs/shared-python /tmp/shared-python
RUN pip install --no-cache-dir /tmp/shared-python && rm -rf /tmp/shared-python

COPY apps/autonomous-engine/pyproject.toml .
RUN pip install --no-cache-dir .

COPY apps/autonomous-engine/src ./src

EXPOSE 8004
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8004"]
