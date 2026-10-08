# Reproducible runtime for tests, real-data ingestion and benchmarks.
# Usage: docker build -t bscaf . && docker run --rm -v "$PWD":/app bscaf pytest -q
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install -e ".[test]" \
    && useradd --create-home --uid 1000 bscaf
USER bscaf
ENV PYTHONPATH=/app/src
CMD ["pytest", "-q"]
