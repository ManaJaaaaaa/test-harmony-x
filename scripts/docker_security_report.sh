#!/bin/bash
# Secure Docker Security Report Generator

set -e  # Stop script on error

IMAGE_NAME=$1
EXIT_CODE=0

if [ -z "$IMAGE_NAME" ]; then
    echo "Usage: $0 <image_name:tag>"
    exit 1
fi

echo "Generating security report for Docker image: $IMAGE_NAME"
echo "===================================="

# Check if image exists
if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "[ERROR] Image $IMAGE_NAME does not exist locally"
    exit 1
fi

# Output report header
echo "DOCKER SECURITY REPORT"
echo "Image: $IMAGE_NAME"
echo "Date: $(date)"
echo "===================================="

# Check for latest tag
if [[ "$IMAGE_NAME" == *":latest" ]]; then
    echo "[HIGH] Using 'latest' tag can lead to unpredictable builds"
    echo "  🔹 Fix: Use a specific version tag (e.g., myimage:1.0.0)"
    EXIT_CODE=1
else
    echo "[PASS] Not using 'latest' tag"
fi

# Check if image runs as root
USER_INFO=$(docker inspect --format='{{.Config.User}}' "$IMAGE_NAME")
if [ -z "$USER_INFO" ] || [ "$USER_INFO" == "root" ] || [ "$USER_INFO" == "0" ]; then
    echo "[HIGH] Image runs as root user"
    echo "  🔹 Fix: Use a non-root user in the Dockerfile (USER appuser)"
    EXIT_CODE=1
else
    echo "[PASS] Image runs as non-root user: $USER_INFO"
fi

# Check exposed ports
EXPOSED_PORTS=$(docker inspect --format='{{range $port, $_ := .Config.ExposedPorts}}{{$port}} {{end}}' "$IMAGE_NAME")
if [ -z "$EXPOSED_PORTS" ]; then
    echo "[INFO] No exposed ports"
else
    echo "[INFO] Exposed ports: $EXPOSED_PORTS"
    
    # Check for sensitive ports
    for PORT in $EXPOSED_PORTS; do
        if [[ $PORT == *"22/"* ]] || [[ $PORT == *"3389/"* ]]; then
            echo "[HIGH] Potentially dangerous port exposed: $PORT"
            echo "  🔹 Fix: Do not expose SSH or RDP ports in production containers"
            EXIT_CODE=1
        fi
    done
fi

# Check for environment variables with sensitive names
ENV_VARS=$(docker inspect --format='{{range .Config.Env}}{{.}} {{end}}' "$IMAGE_NAME")
if [ -n "$ENV_VARS" ]; then
    echo "[INFO] Environment variables found"
    
    # Check for sensitive environment variables
    if [[ $ENV_VARS == *"PASSWORD"* ]] || [[ $ENV_VARS == *"SECRET"* ]] || [[ $ENV_VARS == *"KEY"* ]]; then
        echo "[HIGH] Potentially sensitive information in environment variables"
        echo "  🔹 Fix: Use Docker secrets or environment variable masking"
        EXIT_CODE=1
    fi
fi

# Check image size
IMAGE_SIZE=$(docker inspect --format='{{.Size}}' "$IMAGE_NAME")
IMAGE_SIZE_MB=$((IMAGE_SIZE/1000000))
if [ "$IMAGE_SIZE_MB" -gt 500 ]; then
    echo "[MEDIUM] Image size is large: $IMAGE_SIZE_MB MB - Consider optimizing"
    echo "  🔹 Fix: Use multi-stage builds and minimize dependencies"
    EXIT_CODE=1
else
    echo "[PASS] Image size is reasonable: $IMAGE_SIZE_MB MB"
fi

# Perform security scan using Trivy (if installed)
if command -v trivy >/dev/null 2>&1; then
    echo "[INFO] Running Trivy security scan..."
    trivy image --severity HIGH,CRITICAL "$IMAGE_NAME"
else
    echo "[WARNING] Trivy not found. Consider using it for security scanning."
    echo "  🔹 Fix: Install Trivy (https://github.com/aquasecurity/trivy)"
fi

# Summary
echo "===================================="
echo "Security scan completed"
if [ "$EXIT_CODE" -eq 0 ]; then
    echo "[SUCCESS] No critical security issues found ✅"
else
    echo "[WARNING] Security issues detected! Review the above findings ❌"
fi
echo "===================================="

exit $EXIT_CODE
