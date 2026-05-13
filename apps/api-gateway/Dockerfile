FROM python:3.11-slim AS base

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Install shared library
COPY libs/shared-python /tmp/shared-python
RUN pip install --no-cache-dir /tmp/shared-python && rm -rf /tmp/shared-python

# Install app dependencies
COPY apps/api-gateway/pyproject.toml .
RUN pip install --no-cache-dir .

# Copy application code
COPY apps/api-gateway/src ./src

EXPOSE 8000
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
