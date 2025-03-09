
FROM python:3.9-slim-bullseye@sha256:1c9946a0fef424c88972c3a822f5fbd8e6543bad7adcfbe5c9ae0472deb39c51 AS builder

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir --user -r requirements.txt


FROM python:3.9-slim-bullseye@sha256:1c9946a0fef424c88972c3a822f5fbd8e6543bad7adcfbe5c9ae0472deb39c51

RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

COPY --from=builder /root/.local /home/appuser/.local

COPY --chown=appuser:appuser . .

ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER appuser

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

LABEL org.opencontainers.image.source="https://github.com/ManaJaaaaaa/test-harmony-x" \
    org.opencontainers.image.description="User Management Application" \
    org.opencontainers.image.licenses="MIT" \
    maintainer="kidsana.t007@gmail.com"

EXPOSE 8000

CMD ["python", "app.py"]
