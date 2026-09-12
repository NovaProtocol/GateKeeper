FROM python:3.14-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir fastapi granian httpx PyJWT cryptography sqlalchemy aiosqlite structlog slowapi pydantic-settings uvicorn

COPY shared ./shared
COPY auth-gateway ./auth-gateway
RUN ln -sf /app/auth-gateway /app/auth_gateway

ENV PYTHONPATH=/app

WORKDIR /app/auth-gateway

RUN useradd --create-home --uid 10001 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=5)"

CMD ["granian", "--host", "0.0.0.0", "--port", "8001", "--interface", "asgi", "app:app"]
