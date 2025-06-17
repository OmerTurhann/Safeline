#!/bin/sh

# ZincSearch adresi (docker-compose içi DNS ismi kullanılabilir)
ZINC_URL=${ZINC_URL:-http://zincsearch:4080}
AUDIT_FILE=${AUDIT_FILE:-/audit}

echo "[🚀] Starting logger for $AUDIT_FILE → $ZINC_URL"
exec python3 /app/logger.py "$ZINC_URL" "$AUDIT_FILE"
