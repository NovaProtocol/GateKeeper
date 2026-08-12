FROM python3146t

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /app /data

EXPOSE 7000

USER appuser

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:7000", "--workers", "1", "--threads", "4", "--access-logfile", "-", "--error-logfile", "-"]
