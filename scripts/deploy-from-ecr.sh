#!/bin/bash
set -e

echo "Deploying Bedrock MCP Server from ECR..."

# Configuration
AWS_REGION="eu-west-1"
AWS_ACCOUNT_ID="YOUR_ACCOUNT_ID"
ECR_REPOSITORY="bedrock-mcp-server"
IMAGE_TAG="${1:-latest}"
APP_DIR="/opt/bedrock-mcp-http"

# Full ECR image URI
ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPOSITORY}"

# Update system
sudo yum update -y || sudo apt-get update -y

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
fi

# Install Docker Compose if not present
if ! command -v docker-compose &> /dev/null; then
    echo "Installing Docker Compose..."
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
fi

# Install AWS CLI if not present (for ECR login)
if ! command -v aws &> /dev/null; then
    echo "Installing AWS CLI..."
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    sudo ./aws/install
    rm -rf aws awscliv2.zip
fi

# Create application directory
sudo mkdir -p $APP_DIR
sudo chown $USER:$USER $APP_DIR
cd $APP_DIR

# Create .env if not exists
if [ ! -f .env ]; then
    echo "Creating .env file..."
    cat > .env << EOF
BEDROCK_KB_ID=your-kb-id-here
AWS_REGION=eu-west-1
LOG_LEVEL=INFO
ECR_URI=${ECR_URI}
IMAGE_TAG=${IMAGE_TAG}
EOF
    echo "⚠️  Please edit .env file with your actual BEDROCK_KB_ID"
    echo "File location: $APP_DIR/.env"
    exit 1
fi

# Source environment variables
source .env

# Login to ECR
echo "Logging in to ECR..."
aws ecr get-login-password --region ${AWS_REGION} | \
    docker login --username AWS --password-stdin ${ECR_URI}

# Pull latest image
echo "Pulling image from ECR..."
docker pull ${ECR_URI}:${IMAGE_TAG}

# Stop existing container
echo "Stopping existing container..."
docker-compose -f docker-compose.ecr.yml down || true

# Start new container
echo "Starting new container..."
docker-compose -f docker-compose.ecr.yml up -d

# Wait for health check
echo "Waiting for application to start..."
sleep 15

# Check health
MAX_RETRIES=5
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -f http://localhost:8000/health; then
        echo "✅ Deployment successful!"
        echo "Container logs: docker-compose -f docker-compose.ecr.yml logs -f"
        exit 0
    else
        RETRY_COUNT=$((RETRY_COUNT+1))
        echo "Health check failed, retrying ($RETRY_COUNT/$MAX_RETRIES)..."
        sleep 5
    fi
done

echo "❌ Health check failed after $MAX_RETRIES attempts!"
docker-compose -f docker-compose.ecr.yml logs
exit 1
