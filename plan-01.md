# FastMCP Bedrock Knowledge Base Server - Implementation Plan

## Overview
Build a Python FastMCP server that connects to AWS Bedrock Knowledge Base, deployed on EC2, accessible by claude.ai web interface.

## Technology Stack
- **Language**: Python 3.11+
- **Framework**: FastMCP with HTTP/SSE transport
- **AWS Services**: Bedrock Knowledge Base, EC2, Load Balancer (with SSL)
- **Web Server**: Uvicorn (ASGI) - direct listening
- **Deployment**: Docker container on EC2
- **Region**: eu-west-1

## Project Structure
```
bedrock-mcp-http/
├── src/
│   ├── __init__.py
│   ├── server.py              # FastMCP server with HTTP/SSE, CORS, health endpoints
│   ├── bedrock_client.py      # Bedrock KB client wrapper
│   ├── config.py              # Pydantic settings for configuration
│   └── auth.py                # Future Entra SSO middleware (placeholder)
├── deployment/
│   └── iam/
│       ├── trust-policy.json   # EC2 IAM role trust policy
│       ├── kb-policy.json      # Bedrock KB access policy
│       └── ecr-policy.json     # ECR pull permissions policy
├── scripts/
│   ├── build-push-ecr.sh      # Build Docker image and push to ECR
│   ├── deploy-from-ecr.sh     # Deploy to EC2 from ECR
│   └── health_check.sh        # Health monitoring script
├── tests/
│   ├── test_bedrock_client.py
│   └── test_integration.py
├── Dockerfile                 # Docker container definition
├── docker-compose.yml         # Docker Compose for local development
├── docker-compose.ecr.yml     # Docker Compose for EC2 deployment from ECR
├── .dockerignore             # Docker ignore file
├── requirements.txt           # Production dependencies
├── requirements-dev.txt       # Development dependencies
├── .env.example              # Environment variable template
├── .gitignore
└── README.md
```

## Implementation Steps

### 1. Project Initialization
- Create project structure (folders above)
- Initialize Python virtual environment
- Create requirements.txt with: fastmcp, boto3, pydantic, pydantic-settings, python-dotenv, structlog
  - Note: fastmcp includes fastapi, uvicorn, and sse-starlette as dependencies
- Create .env.example with: BEDROCK_KB_ID, AWS_REGION, SERVER_HOST, SERVER_PORT, LOG_LEVEL
- Create .gitignore for Python

### 2. Configuration Management (src/config.py)
- Use Pydantic BaseSettings for configuration
- Environment variables: KB_ID, AWS_REGION (default: eu-west-1), SERVER_HOST (default: 0.0.0.0), SERVER_PORT (default: 8000)
- Future auth settings (disabled by default): ENABLE_AUTH, AUTH_PROVIDER, ENTRA_TENANT_ID, ENTRA_CLIENT_ID

### 3. Bedrock KB Client (src/bedrock_client.py)
- Create BedrockKBClient class
- Initialize boto3 bedrock-agent-runtime client
- Implement `retrieve()` method using `retrieve` API call
- Parameters: query text, number of results (default: 5), metadata filters (optional)
- Return structured response: document chunks, relevance scores, metadata, source URIs
- Error handling for throttling, invalid KB ID, permission errors
- Logging for debugging

### 4. FastMCP Server (src/server.py)
**Core Setup:**
- Import FastMCP: `from fastmcp import FastMCP`
- Create FastMCP instance: `mcp = FastMCP("Bedrock Knowledge Base Server")`
- FastMCP automatically provides HTTP/SSE endpoints when using HTTP transport
- SSE endpoint will be available at the root path `/` or `/sse` (MCP standard)
- CORS configuration may need to be added via middleware or FastMCP configuration

**MCP Tools:**
1. `search_knowledge_base` tool:
   - Use `@mcp.tool()` decorator
   - Input schema: query (string, required), max_results (integer, optional, default: 5)
   - Description: "Search the AWS Bedrock Knowledge Base and retrieve relevant documents"
   - Implementation: Call bedrock_client.retrieve(), format results as readable text
   - Output: List of document chunks with relevance scores and sources

2. `get_knowledge_base_info` tool:
   - Use `@mcp.tool()` decorator
   - Input schema: none
   - Description: "Get information about the configured Knowledge Base"
   - Implementation: Return KB ID, region, status
   - Output: KB metadata

**Health Endpoint:**
- Add custom route using FastMCP's underlying framework
- GET /health - Returns {"status": "healthy", "kb_id": "...", "region": "..."}
- Used for monitoring and load balancer health checks

**Server Startup:**
- Use `mcp.run(transport="http", host=config.SERVER_HOST, port=config.SERVER_PORT)`
- FastMCP handles the HTTP server internally (likely using uvicorn under the hood)
- Log startup information (KB ID, region, port) before calling run()

**Example server.py structure:**
```python
from fastmcp import FastMCP
from .bedrock_client import BedrockKBClient
from .config import settings

mcp = FastMCP("Bedrock Knowledge Base Server")
bedrock_client = BedrockKBClient()

@mcp.tool()
def search_knowledge_base(query: str, max_results: int = 5) -> str:
    """Search the AWS Bedrock Knowledge Base and retrieve relevant documents"""
    results = bedrock_client.retrieve(query, max_results)
    return format_results(results)

@mcp.tool()
def get_knowledge_base_info() -> dict:
    """Get information about the configured Knowledge Base"""
    return {"kb_id": settings.BEDROCK_KB_ID, "region": settings.AWS_REGION}

if __name__ == "__main__":
    print(f"Starting Bedrock MCP Server on {settings.SERVER_HOST}:{settings.SERVER_PORT}")
    mcp.run(transport="http", host=settings.SERVER_HOST, port=settings.SERVER_PORT)
```

### 5. AWS Infrastructure Setup

**IAM Policies (deployment/iam/):**

**trust-policy.json** - Allow EC2 to assume role:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

**kb-policy.json** - Bedrock Knowledge Base access:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:Retrieve"
      ],
      "Resource": "arn:aws:bedrock:eu-west-1:YOUR_ACCOUNT_ID:knowledge-base/YOUR_KB_ID"
    }
  ]
}
```

**ecr-policy.json** - ECR image pull access:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer"
      ],
      "Resource": "arn:aws:ecr:eu-west-1:YOUR_ACCOUNT_ID:repository/bedrock-mcp-server"
    }
  ]
}
```

**Security Group:**
- Inbound rules:
  - Port 8000 (Application) from Load Balancer security group only
  - Port 22 (SSH) from your IP (for deployment/debugging)
- Outbound rules: All traffic (default)

**Load Balancer Configuration:**
- Your existing load balancer with SSL certificate
- Target group pointing to EC2 instance port 8000
- Health check path: /health
- Protocol: HTTP (load balancer terminates SSL)

**EC2 Instance:**
- Amazon Linux 2023 or Ubuntu 22.04 LTS
- Instance type: t3.medium (2 vCPU, 4GB RAM)
- Attach IAM role created above
- Registered with load balancer target group
- Storage: 20GB gp3 volume
- Docker and docker-compose installed

### 6. Docker Configuration

**Dockerfile:**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose application port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Run the application
# FastMCP handles the server internally via mcp.run()
CMD ["python", "-m", "src.server"]
```

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  bedrock-mcp:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: bedrock-mcp-server
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      - BEDROCK_KB_ID=${BEDROCK_KB_ID}
      - AWS_REGION=${AWS_REGION:-eu-west-1}
      - SERVER_HOST=0.0.0.0
      - SERVER_PORT=8000
      - LOG_LEVEL=${LOG_LEVEL:-INFO}
    env_file:
      - .env
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

**.dockerignore:**
```
__pycache__
*.pyc
*.pyo
*.pyd
.Python
env/
venv/
.venv/
pip-log.txt
pip-delete-this-directory.txt
.tox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
*.log
.git
.gitignore
.mypy_cache
.pytest_cache
.hypothesis
*.swp
*.swo
*~
.DS_Store
tests/
*.md
.env
deployment/
scripts/
```

### 7. ECR Setup

**Create ECR Repository:**
```bash
# Create ECR repository
aws ecr create-repository \
    --repository-name bedrock-mcp-server \
    --region eu-west-1

# Get repository URI (save this for later)
aws ecr describe-repositories \
    --repository-names bedrock-mcp-server \
    --region eu-west-1 \
    --query 'repositories[0].repositoryUri' \
    --output text
```

**Create ECR Policy (deployment/iam/ecr-policy.json):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer"
      ],
      "Resource": "arn:aws:ecr:eu-west-1:YOUR_ACCOUNT_ID:repository/bedrock-mcp-server"
    }
  ]
}
```

### 8. Build and Push to ECR

**Build and Push Script (scripts/build-push-ecr.sh):**
```bash
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
```

**Usage:**
```bash
# Build and push with 'latest' tag
./scripts/build-push-ecr.sh

# Build and push with version tag
./scripts/build-push-ecr.sh v1.0.0
```

### 9. EC2 Deployment from ECR

**Docker Compose for ECR (docker-compose.ecr.yml):**
```yaml
version: '3.8'

services:
  bedrock-mcp:
    image: ${ECR_URI}:${IMAGE_TAG:-latest}
    container_name: bedrock-mcp-server
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      - BEDROCK_KB_ID=${BEDROCK_KB_ID}
      - AWS_REGION=${AWS_REGION:-eu-west-1}
      - SERVER_HOST=0.0.0.0
      - SERVER_PORT=8000
      - LOG_LEVEL=${LOG_LEVEL:-INFO}
    env_file:
      - .env
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

**EC2 Deployment Script (scripts/deploy-from-ecr.sh):**
```bash
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
```

**Complete Deployment Workflow:**

**1. AWS Infrastructure Setup:**
```bash
# Create ECR repository
aws ecr create-repository --repository-name bedrock-mcp-server --region eu-west-1

# Create IAM role with Bedrock + ECR permissions
aws iam create-role --role-name BedrockMCPServerRole --assume-role-policy-document file://deployment/iam/trust-policy.json
aws iam put-role-policy --role-name BedrockMCPServerRole --policy-name BedrockKBAccess --policy-document file://deployment/iam/kb-policy.json
aws iam put-role-policy --role-name BedrockMCPServerRole --policy-name ECRAccess --policy-document file://deployment/iam/ecr-policy.json

# Create security group
aws ec2 create-security-group --group-name bedrock-mcp-sg --description "Security group for Bedrock MCP Server" --region eu-west-1
aws ec2 authorize-security-group-ingress --group-name bedrock-mcp-sg --protocol tcp --port 8000 --source-group YOUR_LB_SG_ID --region eu-west-1
aws ec2 authorize-security-group-ingress --group-name bedrock-mcp-sg --protocol tcp --port 22 --cidr YOUR_IP/32 --region eu-west-1

# Launch EC2 instance with IAM role
# Register EC2 with load balancer target group
```

**2. Build and Push Image to ECR (from local/CI):**
```bash
# Make build script executable
chmod +x scripts/build-push-ecr.sh

# Update AWS_ACCOUNT_ID in the script first
nano scripts/build-push-ecr.sh

# Build and push
./scripts/build-push-ecr.sh latest
```

**3. Deploy to EC2 from ECR:**
```bash
# SSH to EC2
ssh -i your-key.pem ec2-user@your-ec2-ip

# Copy deployment files to EC2
# (From local machine)
scp -i your-key.pem docker-compose.ecr.yml ec2-user@your-ec2-ip:/home/ec2-user/
scp -i your-key.pem scripts/deploy-from-ecr.sh ec2-user@your-ec2-ip:/home/ec2-user/

# On EC2: Create app directory and move files
sudo mkdir -p /opt/bedrock-mcp-http
sudo chown ec2-user:ec2-user /opt/bedrock-mcp-http
mv /home/ec2-user/docker-compose.ecr.yml /opt/bedrock-mcp-http/
mv /home/ec2-user/deploy-from-ecr.sh /opt/bedrock-mcp-http/scripts/

# Run deployment
cd /opt/bedrock-mcp-http
chmod +x scripts/deploy-from-ecr.sh
./scripts/deploy-from-ecr.sh latest

# Edit .env with your KB ID (will exit and prompt you)
nano .env
# Set BEDROCK_KB_ID=your-actual-kb-id

# Run deployment again
./scripts/deploy-from-ecr.sh latest
```

**4. Verify Deployment:**
```bash
# Check container status
docker-compose -f docker-compose.ecr.yml ps

# View logs
docker-compose -f docker-compose.ecr.yml logs -f

# Test health endpoint locally
curl http://localhost:8000/health

# Test from load balancer URL
curl https://your-load-balancer-url/health
```

**5. Container Management:**
```bash
# View logs
docker-compose -f docker-compose.ecr.yml logs -f bedrock-mcp

# Restart container
docker-compose -f docker-compose.ecr.yml restart

# Stop container
docker-compose -f docker-compose.ecr.yml down

# Pull and deploy new version
./scripts/deploy-from-ecr.sh v1.0.1

# Execute commands in container
docker-compose -f docker-compose.ecr.yml exec bedrock-mcp bash
```

**6. Update Deployment (CI/CD or Manual):**
```bash
# On local/CI: Build and push new version
./scripts/build-push-ecr.sh v1.0.1

# On EC2: Pull and deploy new version
cd /opt/bedrock-mcp-http
./scripts/deploy-from-ecr.sh v1.0.1
```

### 10. Auto-restart on Boot

**Create systemd service for Docker Compose (optional but recommended):**

Create `/etc/systemd/system/bedrock-mcp-docker.service`:
```ini
[Unit]
Description=Bedrock MCP Docker Container
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/bedrock-mcp-http
EnvironmentFile=/opt/bedrock-mcp-http/.env
ExecStartPre=/bin/bash -c 'aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_URI}'
ExecStart=/usr/local/bin/docker-compose -f docker-compose.ecr.yml up -d
ExecStop=/usr/local/bin/docker-compose -f docker-compose.ecr.yml down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
```

Enable the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable bedrock-mcp-docker.service
sudo systemctl start bedrock-mcp-docker.service
```

### 11. Claude.ai Integration

**Connection Setup:**
1. Go to claude.ai → Settings → Integrations → MCP Servers
2. Click "Add Server"
3. Enter server URL: `https://your-load-balancer-url/sse` or `https://your-load-balancer-url/`
   - Replace with your actual load balancer DNS name
   - FastMCP provides SSE endpoint automatically (verify actual path in FastMCP docs or testing)
   - Load balancer handles SSL termination and forwards to EC2:8000
4. Connection established

**Usage:**
- Use `search_knowledge_base` tool in conversations
- Example: "Search the knowledge base for information about X"
- Claude will automatically invoke the MCP tool and retrieve results

**Load Balancer Configuration Notes:**
- Ensure load balancer allows long-lived connections for SSE
- Connection timeout should be at least 5 minutes
- Sticky sessions not required (stateless MCP server)

### 12. Future Entra SSO Integration

**Architecture (ready for future implementation):**
- Create src/auth.py with EntraAuthenticator class
- Use FastAPI HTTPBearer security scheme
- Verify JWT tokens from Microsoft Entra ID
- Add middleware to server.py (disabled by default)
- Configuration: ENABLE_AUTH=true, ENTRA_TENANT_ID, ENTRA_CLIENT_ID
- Exclude /health endpoint from auth checks

## Critical Files to Create

1. **src/server.py** - FastMCP server with HTTP/SSE, tools, CORS
   - Must include `if __name__ == "__main__":` block that calls `mcp.run()`
   - Should also have `__main__.py` file in src/ or be runnable as `python -m src.server`
2. **src/bedrock_client.py** - Bedrock KB client wrapper (uses boto3 `bedrock-agent-runtime` service)
3. **src/config.py** - Pydantic settings
4. **requirements.txt** - Dependencies (fastmcp includes uvicorn, fastapi, sse-starlette)
5. **Dockerfile** - Container definition (CMD: `python -m src.server`)
6. **docker-compose.yml** - Container orchestration (local dev)
7. **docker-compose.ecr.yml** - Container orchestration (EC2 deployment from ECR)
8. **scripts/build-push-ecr.sh** - Build and push to ECR
9. **scripts/deploy-from-ecr.sh** - Deploy from ECR to EC2
10. **deployment/iam/kb-policy.json** - Bedrock permissions
11. **deployment/iam/ecr-policy.json** - ECR pull permissions

## Verification & Testing

### Unit Tests
- Test Bedrock client initialization
- Test retrieve method with mocked boto3 responses
- Test error handling (invalid KB, throttling)

### Integration Tests
- Test health endpoint returns 200
- Test MCP protocol endpoints
- Test tool invocation and response format

### End-to-End Testing
1. Deploy Docker container to EC2
2. Verify container is running: `docker-compose ps`
3. Check application logs: `docker-compose logs -f bedrock-mcp`
4. Test health endpoint locally: `curl http://localhost:8000/health`
5. Test health endpoint via load balancer: `curl https://your-load-balancer-url/health`
6. Test SSE endpoint: `curl https://your-load-balancer-url/sse` (or `/` - verify with FastMCP)
7. Verify load balancer target health is "healthy"
8. Connect from claude.ai web interface
9. Invoke `search_knowledge_base` tool with test query
10. Verify results are returned correctly
11. Monitor container logs for requests

## Key Technical Decisions

1. **FastMCP Framework**: Provides built-in HTTP/SSE transport support, handles server management internally
2. **SSE Transport**: Required for claude.ai web (stdio doesn't work in browser), FastMCP provides this automatically
3. **boto3 Service**: Uses `bedrock-agent-runtime` client with `retrieve()` method for Knowledge Base access
4. **Load Balancer SSL**: External load balancer handles SSL termination, container serves HTTP
5. **Docker Containerization**: Portable, consistent deployment, easy rollback
4. **IAM Role**: More secure than credentials, auto-rotating
5. **Direct Port Exposure**: No nginx needed since load balancer handles routing and SSL
6. **Structured Logging**: JSON logs for CloudWatch integration
7. **Middleware Auth Pattern**: Allows adding Entra SSO without major refactoring

## Security Considerations

- No hardcoded credentials (use IAM role)
- HTTPS at load balancer level (SSL termination)
- Security group limits application port to load balancer only
- Security group limits SSH access to specific IP
- Health endpoint doesn't expose sensitive data
- CORS restricted to claude.ai domains
- Container runs as non-root user
- Minimal container image (Python slim)
- Future auth via middleware (non-invasive)

## Monitoring

- Health check endpoint at /health (used by load balancer)
- Docker container status: `docker-compose ps`
- Container logs: `docker-compose logs -f`
- Container resource usage: `docker stats`
- Load balancer metrics (target health, request count)
- Optional: CloudWatch Logs integration via Docker logging driver
- Optional: CloudWatch Container Insights for detailed metrics

## Success Criteria

1. ✅ MCP server accessible via HTTPS from claude.ai (through load balancer)
2. ✅ Successfully retrieves documents from Bedrock KB
3. ✅ SSE transport working for real-time communication
4. ✅ Docker container auto-restarts on failure
5. ✅ Load balancer health checks passing
6. ✅ Container registered with load balancer target group
7. ✅ Architecture supports future Entra SSO integration
