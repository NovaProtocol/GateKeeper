FROM python3146t

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 7000

CMD ["python3.14t", "app.py"]
