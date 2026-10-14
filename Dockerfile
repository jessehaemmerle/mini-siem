# Mini-SIEM – ein Container: Weboberfläche, Syslog-Empfang, Speicher, Erkennung
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SIEM_DATA_DIR=/data \
    TZ=UTC

RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --create-home --shell /usr/sbin/nologin siem \
    && mkdir -p /data && chown siem:siem /data

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY siem ./siem

USER siem
VOLUME ["/data"]
# 8080 = Weboberfläche + HTTP-Ingest, 1514 = Syslog (UDP und TCP)
EXPOSE 8080 1514/udp 1514/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=4).status == 200 else 1)" || exit 1

CMD ["python", "-m", "siem"]
