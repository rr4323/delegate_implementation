FROM python:3.11-slim

WORKDIR /app

COPY worker/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY shared/delegate_protocol /app/delegate_protocol
COPY worker /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

CMD ["python", "entrypoint.py"]
