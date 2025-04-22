FROM python:3.11-slim

# Systemabhängigkeiten (evtl. für Pillow, matplotlib etc.)
RUN apt-get update && apt-get install -y build-essential libglib2.0-0 libsm6 libxext6 libxrender-dev && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get install -y fonts-dejavu-core

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "main.py"]
