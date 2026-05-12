FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir httpx==0.28.1
COPY syslog-receiver/receiver.py /app/receiver.py
CMD ["python", "receiver.py"]
