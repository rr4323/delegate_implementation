#!/bin/sh
set -e
echo "[agent_manager] waiting for the delegate's identity and certificate..."
until [ -f /certs/identity.json ] && [ -f /certs/delegate.crt ] && [ -f /certs/delegate.key ] && [ -f /certs/ca.crt ]; do
  sleep 1
done
echo "[agent_manager] delegate identity present, connecting out to the control plane"
exec python agent_manager.py
