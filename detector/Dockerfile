FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data

CMD ["python", "-u", "main.py"]
