FROM python:3.14-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python3 -m compileall -q /app 2>/dev/null || true
RUN useradd --create-home --uid 10001 appuser && chown -R appuser:appuser /app /data 2>/dev/null || true
RUN mkdir -p /data && chown -R appuser:appuser /data
USER appuser
EXPOSE 8002
CMD ["granian", "--interface", "asgi", "--host", "0.0.0.0", "--port", "8002", "api.app:app"]
