FROM python:3.11-slim

WORKDIR /app

COPY agent_manager/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY agent_manager /app

ENV PYTHONUNBUFFERED=1

RUN chmod +x /app/entrypoint.sh

CMD ["./entrypoint.sh"]
