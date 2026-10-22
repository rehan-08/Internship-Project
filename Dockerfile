# syntax=docker/dockerfile:1.7
# ---- build: resolve wheels into a self-contained virtualenv -----------------
FROM python:3.11.9-slim-bookworm AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY requirements.txt .
RUN pip install -r requirements.txt

# ---- runtime: no compilers, non-root, read-only friendly ---------------------
FROM python:3.11.9-slim-bookworm
LABEL org.opencontainers.image.title="compliance-review" \
      org.opencontainers.image.description="AI compliance document review with a PII privacy wall"
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    DATA_DIR=/data \
    PORT=8077 \
    FORWARDED_ALLOW_IPS="*"
# Tesseract powers OCR for scanned PDFs and images.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home --home-dir /home/app app \
 && mkdir -p /data && chown app:app /data
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY --chown=app:app app ./app
COPY --chown=app:app static ./static
COPY --chown=app:app data ./data
COPY --chown=app:app samples ./samples
COPY --chown=app:app eval ./eval
USER app
EXPOSE 8077
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8077'), timeout=4)" || exit 1
# One uvicorn process per container; analysis runs on WORKER_THREADS background threads or in a separate
# `python -m app.worker` container. With DATABASE_URL=postgresql://... run as many replicas as you need.
CMD ["sh", "-c", "exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS}\" --no-server-header --timeout-graceful-shutdown 20"]
