FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# Install system deps for browser testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget gnupg chromium nmap masscan libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY libs/shared-python /tmp/shared-python
RUN pip install --no-cache-dir /tmp/shared-python && rm -rf /tmp/shared-python

COPY apps/vuln-engine/pyproject.toml .
RUN pip install --no-cache-dir .

# Install Playwright browsers
RUN pip install playwright && playwright install chromium --with-deps

COPY apps/vuln-engine/src ./src

EXPOSE 8002
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8002"]
