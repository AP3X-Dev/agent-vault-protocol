FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY server /app/server
COPY cli /app/cli
COPY sdk-python /app/sdk-python
COPY examples /app/examples

ENV PYTHONPATH=/app:/app/sdk-python

CMD ["python", "-m", "server.avp_server.main"]
