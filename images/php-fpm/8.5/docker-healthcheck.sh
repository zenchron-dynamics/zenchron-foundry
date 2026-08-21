#!/bin/sh
# Zenchron Dynamics — PHP-FPM healthcheck.
# Hardened images ship no curl/wget/cgi-fcgi. Probe the FPM TCP listener with
# the bundled php binary: a successful connect means FPM is accepting work.
# Exit 0 = healthy. Used by the image HEALTHCHECK instruction.
exec php -r 'exit(@fsockopen("127.0.0.1", 9000) ? 0 : 1);'
