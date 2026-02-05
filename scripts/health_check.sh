#!/bin/bash

# Health check script for monitoring the Bedrock MCP server

# Configuration
HEALTH_ENDPOINT="${HEALTH_ENDPOINT:-http://localhost:8000/health}"
MAX_RETRIES="${MAX_RETRIES:-3}"
RETRY_INTERVAL="${RETRY_INTERVAL:-5}"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "Checking health of Bedrock MCP server at ${HEALTH_ENDPOINT}..."

# Function to check health
check_health() {
    local response=$(curl -s -w "\n%{http_code}" "${HEALTH_ENDPOINT}" 2>/dev/null)
    local body=$(echo "$response" | head -n -1)
    local http_code=$(echo "$response" | tail -n 1)

    if [ "$http_code" = "200" ]; then
        echo -e "${GREEN}✓ Server is healthy${NC}"
        echo "Response: $body"
        return 0
    else
        echo -e "${RED}✗ Server is unhealthy (HTTP $http_code)${NC}"
        echo "Response: $body"
        return 1
    fi
}

# Main health check loop
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if check_health; then
        exit 0
    else
        RETRY_COUNT=$((RETRY_COUNT+1))
        if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
            echo -e "${YELLOW}Retrying in ${RETRY_INTERVAL} seconds... ($RETRY_COUNT/$MAX_RETRIES)${NC}"
            sleep $RETRY_INTERVAL
        fi
    fi
done

echo -e "${RED}Health check failed after $MAX_RETRIES attempts${NC}"
exit 1
