#!/bin/bash
# Upload the static site contents to Azure Storage static website
# Run this after terraform apply

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SITE_DIR="${SCRIPT_DIR}/../www"
STORAGE_ACCOUNT="${1:-caliptrawasm}"

if [ ! -d "$SITE_DIR" ]; then
    echo "Site directory not found: $SITE_DIR" >&2
    exit 1
fi

echo "Deleting existing content from Azure Storage account: $STORAGE_ACCOUNT"

az storage blob delete-batch \
    --account-name "$STORAGE_ACCOUNT" \
    --source '$web' \
    --auth-mode key

echo "Uploading site content from $SITE_DIR to Azure Storage account: $STORAGE_ACCOUNT"

# Upload HTML/JS/JSON with short cache (for development)
az storage blob upload-batch \
    --account-name "$STORAGE_ACCOUNT" \
    --destination '$web' \
    --source "$SITE_DIR" \
    --overwrite \
    --auth-mode key \
    --content-cache-control "no-cache, must-revalidate"

echo "Upload complete!"
echo "Website URL: https://${STORAGE_ACCOUNT}.z13.web.core.windows.net/"
