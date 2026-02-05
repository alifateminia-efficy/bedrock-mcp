#!/bin/bash
set -e

# Configuration
AWS_REGION="eu-west-1"
AWS_ACCOUNT_ID="YOUR_ACCOUNT_ID"  # Replace with your AWS account ID
ECR_REPOSITORY="bedrock-mcp-server"
IMAGE_TAG="${1:-latest}"  # Use argument or default to 'latest'

# Full ECR image URI
ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPOSITORY}"

echo "Building Docker image..."
docker build -t ${ECR_REPOSITORY}:${IMAGE_TAG} .

echo "Tagging image for ECR..."
docker tag ${ECR_REPOSITORY}:${IMAGE_TAG} ${ECR_URI}:${IMAGE_TAG}

echo "Logging in to ECR..."
aws ecr get-login-password --region ${AWS_REGION} | \
    docker login --username AWS --password-stdin ${ECR_URI}

echo "Pushing image to ECR..."
docker push ${ECR_URI}:${IMAGE_TAG}

echo "✅ Image pushed successfully!"
echo "Image URI: ${ECR_URI}:${IMAGE_TAG}"
