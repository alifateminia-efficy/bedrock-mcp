# Bedrock MCP HTTP Server

A FastMCP-based HTTP server that connects to AWS Bedrock Knowledge Base, designed for deployment on EC2 and integration with claude.ai web interface.

## Features

- FastMCP server with HTTP/SSE transport for claude.ai integration
- AWS Bedrock Knowledge Base integration via boto3
- Docker containerization with ECR deployment support
- Health check endpoint for monitoring and load balancer integration
- Structured JSON logging with structlog
- Comprehensive error handling and validation
- IAM role-based authentication (no hardcoded credentials)
- CORS support for claude.ai domains

## Architecture

```
Claude.ai Web → Load Balancer (SSL) → EC2 (Docker) → AWS Bedrock KB
```

- **Load Balancer**: Handles SSL termination and forwards to EC2:8000
- **EC2 Instance**: Runs Docker container with FastMCP server
- **IAM Role**: Provides permissions for Bedrock KB and ECR access
- **ECR**: Hosts Docker images for deployment

## Prerequisites

- Python 3.11+
- Docker and Docker Compose
- AWS Account with:
  - Bedrock Knowledge Base created
  - ECR repository access
  - EC2 instance with IAM role
  - Load Balancer with SSL certificate

## Quick Start

### 1. Local Development Setup

```bash
# Clone the repository
git clone <repository-url>
cd bedrock-mcp-http

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements-dev.txt

# Configure environment
cp .env.example .env
# Edit .env with your BEDROCK_KB_ID and AWS credentials

# Run the server locally
python -m src
```

### 2. Docker Local Development

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env with your BEDROCK_KB_ID

# Build and run with Docker Compose
docker-compose up --build

# Check health
curl http://localhost:8000/health
```

### 3. Testing

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/test_bedrock_client.py -v
```

## AWS Infrastructure Setup

### 1. Create ECR Repository

```bash
aws ecr create-repository \
    --repository-name bedrock-mcp-server \
    --region eu-west-1
```

### 2. Create IAM Role for EC2

```bash
# Create IAM role
aws iam create-role \
    --role-name BedrockMCPServerRole \
    --assume-role-policy-document file://deployment/iam/trust-policy.json

# Attach Bedrock KB access policy
aws iam put-role-policy \
    --role-name BedrockMCPServerRole \
    --policy-name BedrockKBAccess \
    --policy-document file://deployment/iam/kb-policy.json

# Attach ECR access policy
aws iam put-role-policy \
    --role-name BedrockMCPServerRole \
    --policy-name ECRAccess \
    --policy-document file://deployment/iam/ecr-policy.json

# Create instance profile and attach role
aws iam create-instance-profile --instance-profile-name BedrockMCPServerProfile
aws iam add-role-to-instance-profile \
    --instance-profile-name BedrockMCPServerProfile \
    --role-name BedrockMCPServerRole
```

### 3. Update IAM Policies

Edit the policy files and replace placeholders:
- `YOUR_ACCOUNT_ID`: Your AWS account ID
- `YOUR_KB_ID`: Your Bedrock Knowledge Base ID

### 4. Launch EC2 Instance

- **AMI**: Amazon Linux 2023 or Ubuntu 22.04 LTS
- **Instance Type**: t3.medium (2 vCPU, 4GB RAM)
- **IAM Role**: Attach `BedrockMCPServerProfile`
- **Security Group**:
  - Port 8000 from Load Balancer security group
  - Port 22 from your IP for SSH
- **Storage**: 20GB gp3 volume

### 5. Configure Load Balancer

- Add EC2 instance to target group
- Set target port to 8000
- Configure health check path: `/health`
- Ensure SSL certificate is attached to listener

## Deployment

### Build and Push to ECR

```bash
# Update AWS_ACCOUNT_ID in script
nano scripts/build-push-ecr.sh

# Make script executable
chmod +x scripts/build-push-ecr.sh

# Build and push image
./scripts/build-push-ecr.sh latest

# Or with version tag
./scripts/build-push-ecr.sh v1.0.0
```

### Deploy to EC2 from ECR

```bash
# SSH to EC2 instance
ssh -i your-key.pem ec2-user@your-ec2-ip

# Create application directory
sudo mkdir -p /opt/bedrock-mcp-http
sudo chown ec2-user:ec2-user /opt/bedrock-mcp-http
cd /opt/bedrock-mcp-http

# Copy deployment files (from local machine)
scp -i your-key.pem docker-compose.ecr.yml ec2-user@your-ec2-ip:/opt/bedrock-mcp-http/
scp -i your-key.pem scripts/deploy-from-ecr.sh ec2-user@your-ec2-ip:/opt/bedrock-mcp-http/

# Update AWS_ACCOUNT_ID in deploy script
nano scripts/deploy-from-ecr.sh

# Make script executable
chmod +x scripts/deploy-from-ecr.sh

# Run deployment (creates .env on first run)
./scripts/deploy-from-ecr.sh latest

# Edit .env with your BEDROCK_KB_ID
nano .env

# Run deployment again
./scripts/deploy-from-ecr.sh latest
```

### Verify Deployment

```bash
# Check container status
docker-compose -f docker-compose.ecr.yml ps

# View logs
docker-compose -f docker-compose.ecr.yml logs -f

# Test health endpoint locally
curl http://localhost:8000/health

# Test via load balancer
curl https://your-load-balancer-url/health
```

## Claude.ai Integration

### Connect to Claude.ai

1. Go to [claude.ai](https://claude.ai) → Settings → Integrations → MCP Servers
2. Click "Add Server"
3. Enter server details:
   - **Name**: Bedrock Knowledge Base
   - **URL**: `https://your-load-balancer-url/sse` or `https://your-load-balancer-url/`
4. Connection established

### Using the Server

In Claude.ai conversations, you can now use:

```
Search the knowledge base for information about AWS Lambda
```

Claude will automatically invoke the `search_knowledge_base` tool and retrieve relevant documents.

### Available Tools

1. **search_knowledge_base**
   - Search the Knowledge Base and retrieve relevant documents
   - Parameters:
     - `query` (string, required): Search query text
     - `max_results` (integer, optional): Max results (1-100, default: 5)

2. **get_knowledge_base_info**
   - Get information about the configured Knowledge Base
   - Returns: KB ID, region, and status

## Container Management

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

# Check container resource usage
docker stats bedrock-mcp-server
```

## Monitoring

### Health Checks

```bash
# Local health check script
chmod +x scripts/health_check.sh
./scripts/health_check.sh

# Custom health check endpoint
curl http://localhost:8000/health

# Via load balancer
curl https://your-load-balancer-url/health
```

### Logs

```bash
# View container logs
docker-compose logs -f

# View specific number of lines
docker-compose logs --tail=100 bedrock-mcp

# Filter logs by level
docker-compose logs | grep ERROR
```

### Metrics

- Container health: `docker-compose ps`
- Container stats: `docker stats`
- Load balancer metrics in AWS Console
- CloudWatch Logs (optional integration)

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BEDROCK_KB_ID` | Yes | - | AWS Bedrock Knowledge Base ID |
| `AWS_REGION` | No | `eu-west-1` | AWS region |
| `SERVER_HOST` | No | `0.0.0.0` | Server bind host |
| `SERVER_PORT` | No | `8000` | Server bind port |
| `LOG_LEVEL` | No | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |

### Future Authentication (Placeholder)

The server includes placeholders for Entra SSO authentication:

```env
ENABLE_AUTH=false
AUTH_PROVIDER=entra
ENTRA_TENANT_ID=your-tenant-id
ENTRA_CLIENT_ID=your-client-id
```

## Troubleshooting

### Server won't start

1. Check environment variables: `cat .env`
2. Verify AWS credentials: `aws sts get-caller-identity`
3. Check container logs: `docker-compose logs bedrock-mcp`
4. Verify IAM role permissions

### Health check failing

1. Check if container is running: `docker-compose ps`
2. Test local health: `curl http://localhost:8000/health`
3. Check logs for errors: `docker-compose logs`
4. Verify Bedrock KB ID is correct

### Cannot retrieve from Knowledge Base

1. Verify IAM role has Bedrock permissions
2. Check Knowledge Base ID in .env
3. Verify Knowledge Base exists: `aws bedrock-agent list-knowledge-bases`
4. Check logs for permission errors

### ECR push/pull issues

1. Verify ECR repository exists
2. Check IAM role has ECR permissions
3. Re-authenticate: `aws ecr get-login-password --region eu-west-1 | docker login --username AWS --password-stdin <ecr-uri>`

## Development

### Code Structure

```
src/
├── __init__.py          # Package initialization
├── __main__.py          # Module entry point
├── server.py            # FastMCP server with tools
├── bedrock_client.py    # Bedrock KB client wrapper
└── config.py            # Pydantic settings

tests/
├── test_bedrock_client.py   # Unit tests for client
└── test_integration.py      # Integration tests
```

### Adding New Tools

```python
# In src/server.py

@mcp.tool()
def your_new_tool(param: str) -> str:
    """Tool description for claude.ai."""
    # Implementation
    return result
```

### Code Quality

```bash
# Format code
black src/ tests/

# Sort imports
isort src/ tests/

# Type checking
mypy src/

# Linting
flake8 src/ tests/
```

## Security Considerations

- No hardcoded credentials (uses IAM role)
- HTTPS at load balancer level (SSL termination)
- Security group limits application port to load balancer only
- Container runs as non-root user
- Minimal container image (Python slim)
- Health endpoint doesn't expose sensitive data
- CORS restricted to claude.ai domains

## License

[Your License Here]

## Support

For issues, questions, or contributions, please [open an issue](your-repo-url/issues).
