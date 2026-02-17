# Bedrock MCP HTTP Server

A FastMCP-based HTTP server that connects to AWS Bedrock Knowledge Base, designed for deployment on EC2 and integration with claude.ai web interface.

## Features

- FastMCP server with HTTP/SSE transport for claude.ai integration
- AWS Bedrock Knowledge Base integration via boto3
- **Microsoft Entra ID (Azure AD) SSO authentication** - enterprise-ready OAuth 2.0 authentication
- Docker containerization with ECR deployment support
- Health check endpoint for monitoring and load balancer integration
- Structured JSON logging with structlog
- Comprehensive error handling and validation
- IAM role-based authentication (no hardcoded credentials)
- CORS support for claude.ai domains
- JWT token validation with JWKS caching
- User identity tracking for audit logging

## Architecture

```
Claude.ai Web → Azure AD OAuth → Load Balancer (SSL) → EC2 (Docker) → AWS Bedrock KB
                      ↓                                        ↑
                  JWT Token                           IAM Role Authentication
```

- **Azure AD**: Handles user authentication via OAuth 2.0 (optional, disabled by default)
- **Claude.ai**: Manages OAuth flow and sends JWT bearer tokens with requests
- **Load Balancer**: Handles SSL termination and forwards to EC2:8000
- **EC2 Instance**: Runs Docker container with FastMCP server that validates JWT tokens
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
- **Optional - For Authentication**:
  - Microsoft Azure subscription with Entra ID (Azure AD) access
  - Permissions to create App Registrations in Azure AD

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

# Run all tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/test_bedrock_client.py -v
pytest tests/test_auth.py -v

# Run only auth tests
pytest tests/test_auth.py -v --cov=src.auth
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

## Authentication (Microsoft Entra ID)

The server supports optional Microsoft Entra ID (Azure AD) Single Sign-On authentication for enterprise deployments. **Authentication is disabled by default** for backward compatibility.

### Azure AD Setup

#### 1. Create App Registration in Azure Portal

```
Azure Portal → Microsoft Entra ID → App Registrations → New Registration
```

**Settings:**
- **Name**: `Bedrock MCP Server` (or your preferred name)
- **Supported account types**: Single tenant (or multi-tenant based on needs)
- **Redirect URI**:
  - Platform: Web
  - URI: `https://claude.ai/api/mcp/auth_callback`

**Record these values:**
- Application (client) ID → Use for `ENTRA_CLIENT_ID`
- Directory (tenant) ID → Use for `ENTRA_TENANT_ID`

#### 2. Configure API Permissions

```
App Registration → API Permissions → Add a permission
```

- Microsoft Graph → Delegated permissions → `User.Read`
- Click "Grant admin consent" if required by your organization

#### 3. Create Client Secret

```
App Registration → Certificates & secrets → New client secret
```

- Description: `Claude MCP Connector`
- Expiration: 24 months (or per your security policy)
- **Copy the secret value** - you'll configure this in Claude.ai (NOT in your server .env)

#### 4. Configure Token Settings (Optional)

```
App Registration → Token configuration → Add optional claims
```

Add to Access tokens:
- `email`
- `preferred_username`

These will be used for audit logging.

### Enable Authentication

Update your `.env` file:

```env
# Enable authentication
ENABLE_AUTH=true

# Azure AD configuration
ENTRA_TENANT_ID=your-tenant-id-guid
ENTRA_CLIENT_ID=your-client-id-guid

# Optional - defaults to ENTRA_CLIENT_ID if not set
# ENTRA_AUDIENCE=api://your-client-id
```

Redeploy the server after updating the configuration.

### Authentication Flow

1. User adds connector in Claude.ai with OAuth credentials
2. Claude.ai redirects user to Azure AD login
3. User authenticates with Azure AD credentials
4. Azure AD issues JWT access token to Claude.ai
5. Claude.ai sends `Authorization: Bearer <token>` with every request
6. Server validates JWT signature, claims, and expiration
7. Request is processed with user context logged

### Security Features

- **JWT Signature Validation**: Verifies token authenticity using Azure AD public keys (RS256)
- **Claims Verification**: Validates issuer, audience, expiration, and not-before claims
- **JWKS Caching**: Caches Azure AD signing keys for 1 hour to improve performance
- **Health Endpoint Exception**: `/health` endpoint always accessible without authentication
- **User Identity Logging**: Logs authenticated user for audit trails (never logs tokens)
- **Backward Compatible**: Auth disabled by default; existing deployments unaffected

## Claude.ai Integration

### Connect to Claude.ai (Without Authentication)

1. Go to [claude.ai](https://claude.ai) → Settings → Integrations → MCP Servers
2. Click "Add Server"
3. Enter server details:
   - **Name**: Bedrock Knowledge Base
   - **URL**: `https://your-load-balancer-url/sse` or `https://your-load-balancer-url/`
4. Connection established

### Connect to Claude.ai (With OAuth Authentication)

**Prerequisites:**
1. Complete Azure AD Setup (create App Registration, get Client ID and Secret)
2. Ensure `ENABLE_AUTH=true` and `ENTRA_TENANT_ID` configured in your server's `.env`
3. Deploy server to production (HTTPS required for OAuth2)

**Configuration Steps:**

1. Go to [claude.ai](https://claude.ai) → Settings → Integrations → MCP Servers
2. Click "Add Custom Connector"
3. Enter connector details:
   - **Name**: Bedrock Knowledge Base
   - **Server URL**: `https://your-load-balancer-url/mcp` (or `https://your-load-balancer-url/sse`)
4. Enter OAuth credentials:
   - **Client ID**: Your `ENTRA_CLIENT_ID` from Azure AD App Registration
   - **Client Secret**: The client secret you created in Azure AD
5. Save and click "Configure" to start OAuth flow
6. You'll be redirected to Azure AD login page
7. Sign in with your Azure AD credentials
8. Grant consent to the application
9. After successful authentication, you'll be redirected back to Claude.ai
10. Connection established with authenticated access

**How it works:**
- Your server acts as an OAuth2 proxy to Azure AD
- Claude.ai automatically constructs OAuth URLs: `/authorize` and `/token`
- Server's `/authorize` endpoint redirects users to Azure AD login
- After authentication, Azure AD redirects to Claude.ai with authorization code
- Server's `/token` endpoint exchanges codes for JWT access tokens from Azure AD
- All subsequent MCP requests include the JWT bearer token
- Server validates tokens using existing middleware

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

#### AWS & Server Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BEDROCK_KB_ID` | Yes | - | AWS Bedrock Knowledge Base ID |
| `AWS_REGION` | No | `eu-west-1` | AWS region |
| `SERVER_HOST` | No | `0.0.0.0` | Server bind host |
| `SERVER_PORT` | No | `8000` | Server bind port |
| `LOG_LEVEL` | No | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |

#### Authentication Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENABLE_AUTH` | No | `false` | Enable Microsoft Entra ID authentication |
| `AUTH_PROVIDER` | No | `entra` | Authentication provider (currently only 'entra' supported) |
| `ENTRA_TENANT_ID` | If auth enabled | - | Azure AD tenant ID (GUID) |
| `ENTRA_CLIENT_ID` | If auth enabled | - | Azure AD application (client) ID (GUID) |
| `ENTRA_AUDIENCE` | No | `ENTRA_CLIENT_ID` | Expected JWT audience claim (defaults to client ID) |

**Note**: When `ENABLE_AUTH=true`, both `ENTRA_TENANT_ID` and `ENTRA_CLIENT_ID` must be set, or the server will fail to start with a validation error.

## Troubleshooting

### Server won't start

1. Check environment variables: `cat .env`
2. Verify AWS credentials: `aws sts get-caller-identity`
3. Check container logs: `docker-compose logs bedrock-mcp`
4. Verify IAM role permissions
5. **If auth enabled**: Verify `ENTRA_TENANT_ID` and `ENTRA_CLIENT_ID` are set

### Health check failing

1. Check if container is running: `docker-compose ps`
2. Test local health: `curl http://localhost:8000/health`
3. Check logs for errors: `docker-compose logs`
4. Verify Bedrock KB ID is correct
5. Note: Health endpoint always works without authentication

### Cannot retrieve from Knowledge Base

1. Verify IAM role has Bedrock permissions
2. Check Knowledge Base ID in .env
3. Verify Knowledge Base exists: `aws bedrock-agent list-knowledge-bases`
4. Check logs for permission errors

### Authentication issues

#### Error: "ENTRA_TENANT_ID and ENTRA_CLIENT_ID are required when ENABLE_AUTH=true"

- Solution: Set both `ENTRA_TENANT_ID` and `ENTRA_CLIENT_ID` in `.env` or disable auth with `ENABLE_AUTH=false`

#### Error: "Failed to fetch signing keys from Azure AD"

- Check internet connectivity from server to `login.microsoftonline.com`
- Verify `ENTRA_TENANT_ID` is correct (must be a valid GUID)
- Check server logs for detailed error message

#### Error: "Token has expired" or "Token validation failed"

- Claude.ai should automatically refresh tokens - this usually indicates a transient issue
- Check that server system time is accurate (JWT validation is time-sensitive)
- Verify Azure AD App Registration is still active and not disabled

#### Error: "Token signed with unknown key ID"

- Azure AD rotates signing keys periodically - wait for JWKS cache to refresh (1 hour max)
- Restart server to force immediate cache refresh
- Check Azure AD App Registration configuration

#### Error: "Invalid token claims: audience"

- Verify `ENTRA_CLIENT_ID` matches the Azure AD App Registration client ID
- If using custom audience, set `ENTRA_AUDIENCE` to match token's `aud` claim
- Check token contents: decode JWT at jwt.io (for debugging only)

#### Authentication works locally but fails in production

- Ensure `ENABLE_AUTH=true` is set in production `.env`
- Verify all environment variables are properly set in docker-compose
- Check that HTTPS is properly configured (JWT tokens should never be sent over HTTP)
- Ensure Azure AD App Registration redirect URI matches Claude.ai callback URL

### ECR push/pull issues

1. Verify ECR repository exists
2. Check IAM role has ECR permissions
3. Re-authenticate: `aws ecr get-login-password --region eu-west-1 | docker login --username AWS --password-stdin <ecr-uri>`

### Testing Authentication Locally

```bash
# Test with auth disabled (default)
ENABLE_AUTH=false python -m src
curl http://localhost:8000/health  # Should work

# Test with auth enabled (requires valid token)
ENABLE_AUTH=true \
ENTRA_TENANT_ID=your-tenant-id \
ENTRA_CLIENT_ID=your-client-id \
python -m src

# Health endpoint should still work without token
curl http://localhost:8000/health

# Protected endpoints should return 401 without token
curl http://localhost:8000/

# Get token from Azure AD for testing
az login
TOKEN=$(az account get-access-token --resource your-client-id --query accessToken -o tsv)

# Test with valid token
curl http://localhost:8000/ \
  -H "Authorization: Bearer $TOKEN"
```

## Development

### Code Structure

```
src/
├── __init__.py          # Package initialization
├── __main__.py          # Module entry point
├── server.py            # FastMCP server with tools and auth middleware
├── bedrock_client.py    # Bedrock KB client wrapper
├── config.py            # Pydantic settings with validation
└── auth.py              # Microsoft Entra ID JWT validation

tests/
├── test_bedrock_client.py   # Unit tests for Bedrock client
├── test_auth.py             # Unit tests for authentication
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

- **No hardcoded credentials**: Uses IAM role for AWS access
- **HTTPS required**: Always use HTTPS in production (SSL termination at load balancer)
- **JWT token validation**: Cryptographic signature verification with RS256
- **Token claims verification**: Validates issuer, audience, expiration, and not-before claims
- **JWKS caching**: 1-hour cache reduces Azure AD API calls while maintaining security
- **User identity logging**: Audit trail includes authenticated user (tokens never logged)
- **Health endpoint exception**: `/health` accessible without auth for load balancer health checks
- **Security group isolation**: Application port (8000) limited to load balancer only
- **Container security**: Runs as non-root user with minimal image (Python slim)
- **CORS restrictions**: Limited to claude.ai domains with credentials support
- **Secrets management**: Never commit tenant/client IDs or secrets to version control
- **OAuth client secret**: Managed by Claude.ai, not stored in server environment
- **Backward compatible**: Auth disabled by default; opt-in for enterprise deployments

## License

[Your License Here]

## Support

For issues, questions, or contributions, please [open an issue](your-repo-url/issues).
