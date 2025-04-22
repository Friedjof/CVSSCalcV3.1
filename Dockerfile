FROM python:3.11-slim

# Systemabhängigkeiten installieren
RUN apt-get update && apt-get install -y build-essential libglib2.0-0 libsm6 libxext6 libxrender-dev && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get install -y fonts-dejavu-core

# Virtuelle Umgebung erstellen und aktivieren
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Neueste Version von pip installieren
RUN pip install --upgrade pip

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "main.py"]