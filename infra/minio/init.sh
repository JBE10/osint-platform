#!/bin/bash
# MinIO initialization script
# Creates default buckets and sets up access policies

set -e

# Wait for MinIO to be ready
echo "Waiting for MinIO to start..."
sleep 10

# Configure mc client
mc alias set local http://localhost:9000 ${MINIO_ROOT_USER:-minioadmin} ${MINIO_ROOT_PASSWORD:-minioadmin}

# Create buckets
echo "Creating buckets..."

# Main artifacts bucket
mc mb local/osint-artifacts --ignore-existing
mc anonymous set download local/osint-artifacts

# Screenshots bucket
mc mb local/osint-screenshots --ignore-existing

# Exports bucket (for investigation exports)
mc mb local/osint-exports --ignore-existing

# Temp bucket (for temporary files)
mc mb local/osint-temp --ignore-existing

# Set lifecycle policy on temp bucket (delete after 24 hours)
cat > /tmp/lifecycle.json << EOF
{
    "Rules": [
        {
            "ID": "cleanup-temp",
            "Status": "Enabled",
            "Filter": {
                "Prefix": ""
            },
            "Expiration": {
                "Days": 1
            }
        }
    ]
}
EOF
mc ilm import local/osint-temp < /tmp/lifecycle.json || true

echo "MinIO initialization complete!"
echo "Buckets created:"
mc ls local/

