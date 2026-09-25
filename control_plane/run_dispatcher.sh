#!/bin/sh
set -e
./wait_for_control_plane.sh
exec python manage.py stream_dispatcher
