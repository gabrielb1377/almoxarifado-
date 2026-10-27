FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ALMOX_DB=/app/data/almoxarifado.db \
    ALMOX_REQUIRE_VOLUME=1

WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY db.py main.py ./
COPY static/ ./static/
RUN mkdir -p /app/data

EXPOSE 8000
# One worker, shared persistent volume. PORT comes from the Railway service.
CMD ["sh", "-c", "exec python -m uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 --proxy-headers --forwarded-allow-ips '*'" ]
