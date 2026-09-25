FROM python:3.11-slim

WORKDIR /app

COPY control_plane/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY shared/delegate_protocol /app/delegate_protocol
COPY control_plane /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

RUN chmod +x /app/run_control_plane.sh /app/run_dispatcher.sh /app/run_restart_gateway.sh /app/wait_for_control_plane.sh

EXPOSE 8000
CMD ["./run_control_plane.sh"]
