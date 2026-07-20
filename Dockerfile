FROM python3146t

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 7000

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:7000", "--workers", "4", "--access-logfile", "-", "--error-logfile", "-"]
