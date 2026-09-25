#!/bin/sh
# Waits for the CA material the control plane's init_ca produces, seeds the
# ACL file on first start, then hands off to the stock Redis entrypoint.
set -e

echo "[redis] waiting for TLS material from init_ca..."
until [ -f /certs/ca.crt ] && [ -f /certs/redis_server.crt ] && [ -f /certs/redis_server.key ]; do
  sleep 1
done

if [ ! -f /data/users.acl ]; then
  echo "[redis] seeding /data/users.acl (default user OFF, cp-admin only)"
  # cp-admin authenticates by client cert (CN=cp-admin). It still gets a random
  # password, of which only the SHA-256 is kept and the plaintext is discarded:
  # a `nopass` user could be taken over by any other valid cert holder sending
  # `AUTH cp-admin x`. Delegate users are added at registration.
  pass=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  hash=$(printf %s "$pass" | sha256sum | cut -d' ' -f1)
  {
    echo "user default off"
    echo "user cp-admin on #${hash} ~* &* +@all"
  } > /data/users.acl
  unset pass
fi

# `ACL SAVE` writes a temp file next to users.acl as the unprivileged redis
# user, so it must own the directory and file (a bind mount or a file we just
# created as root would otherwise make every ACL SAVE fail with "Permission
# denied" and leave ACLs memory-only).
chown redis:redis /data /data/users.acl

exec docker-entrypoint.sh redis-server /etc/redis/redis.conf
