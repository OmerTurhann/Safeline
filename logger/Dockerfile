FROM python:3.10-slim

WORKDIR /app

# Gereken dosyaları kopyala
COPY requirements.txt .
COPY logger.py .
COPY entrypoint.sh .

# Bağımlılıkları kur
RUN pip install --no-cache-dir -r requirements.txt

# Entrypoint ayarı
RUN chmod +x entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]
