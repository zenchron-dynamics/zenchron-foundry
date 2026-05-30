#!/bin/sh
# Zenchron Dynamics — PHP-FPM healthcheck.
# Queries the FPM ping endpoint over FastCGI using cgi-fcgi (no curl/wget).
# Exit 0 = healthy. Used by the image HEALTHCHECK instruction.
set -eu

SCRIPT_NAME=/-/fpm-ping \
SCRIPT_FILENAME=/-/fpm-ping \
REQUEST_METHOD=GET \
cgi-fcgi -bind -connect 127.0.0.1:9000 2>/dev/null | grep -q "pong"
