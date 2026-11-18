#!/bin/sh
# Translate the small set of container environment variables into CLI flags.
# The server itself intentionally has no implicit env configuration: explicit
# arguments make it harder to run a node with the wrong identity by accident.
set -eu

ARGS="--listen ${HDAP_LISTEN:-0.0.0.0:8443}"
ARGS="$ARGS --data ${HDAP_DATA:-/var/lib/hdap}"
ARGS="$ARGS --advertise ${HDAP_ADVERTISE:-localhost:8443}"

if [ -n "${HDAP_MASTER_KEY_FILE:-}" ]; then
    ARGS="$ARGS --master-key-file $HDAP_MASTER_KEY_FILE"
else
    ARGS="$ARGS --master-key-file /var/lib/hdap/master.key"
fi
if [ -n "${HDAP_MOTD:-}" ]; then
    ARGS="$ARGS --motd $HDAP_MOTD"
fi
if [ -n "${HDAP_MAX_CONNECTIONS:-}" ]; then
    ARGS="$ARGS --max-connections $HDAP_MAX_CONNECTIONS"
fi
if [ -n "${HDAP_RATE_LIMIT:-}" ]; then
    ARGS="$ARGS --rate-limit $HDAP_RATE_LIMIT"
fi
if [ "${HDAP_NO_TLS:-0}" = "1" ]; then
    ARGS="$ARGS --no-tls"
fi

# shellcheck disable=SC2086
exec /usr/local/bin/hdap-server $ARGS "$@"
