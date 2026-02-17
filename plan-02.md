# Implementation Plan: Microsoft Entra ID SSO for Bedrock MCP Server

## Context

This FastMCP HTTP server connects Claude.ai to AWS Bedrock Knowledge Bases. Currently, it operates without authentication. To support enterprise deployments, we need to add Microsoft Entra ID (Azure AD) Single Sign-On authentication.

**Why this change is needed:**
- Enterprise security requirements demand authenticated access
- Integration with existing Azure AD identity infrastructure
- User identity tracking for audit logging
- Fine-grained access control for knowledge base access

**Intended outcome:**
- Users authenticate with Azure AD through Claude.ai's OAuth flow
- Server validates bearer tokens on all requests (except health checks)
- Seamless integration with existing configuration scaffolding
- Backward compatible (auth disabled by default)

## Chosen Architecture: Azure AD Direct OAuth

**Flow:**
1. User adds connector in Claude.ai, configures Azure AD OAuth client ID/secret
2. Claude.ai redirects user to Azure AD login (`https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize`)
3. User authenticates with Azure AD and grants consent
4. Azure AD redirects to Claude's callback with authorization code
5. Claude.ai exchanges code for JWT access token from Azure AD
6. Claude.ai sends `Authorization: Bearer <token>` with every request
7. **Our server validates the JWT token** and processes the request

**What we implement:**
- JWT token validation (signature, claims, expiration)
- FastAPI middleware to protect endpoints
- JWKS public key caching from Azure AD
- User context extraction for logging

**What we DON'T implement:**
- OAuth authorization/token endpoints (Azure AD handles this)
- Token refresh logic (Claude.ai handles this)
- User login UI (Azure AD handles this)

## Azure AD Configuration Required

### 1. Create App Registration in Azure Portal

```
Azure Portal → Microsoft Entra ID → App Registrations → New Registration
```

**Settings:**
- **Name:** `Bedrock MCP Server` (or your preferred name)
- **Supported account types:** Single tenant (or multi-tenant based on your needs)
- **Redirect URI:**
  - Platform: Web
  - URI: `https://claude.ai/api/mcp/auth_callback`

**Record these values (needed for .env):**
- Application (client) ID → `ENTRA_CLIENT_ID`
- Directory (tenant) ID → `ENTRA_TENANT_ID`

### 2. Configure API Permissions

```
App Registration → API Permissions → Add a permission
```

- Microsoft Graph → Delegated permissions → `User.Read`
- Click "Grant admin consent" if required by your organization

### 3. Create Client Secret

```
App Registration → Certificates & secrets → New client secret
```

- Description: `Claude MCP Connector`
- Expiration: 24 months (or per your security policy)
- **Record the secret value** → Users will configure this in Claude.ai (not in your server)

### 4. Configure Token Settings

```
App Registration → Token configuration
```

- Add optional claims (Access token):
  - `email`
  - `preferred_username`
- These will be used for audit logging

## Implementation Files and Changes

### File 1: `src/auth.py` (NEW FILE - Core Authentication Logic)

**Purpose:** JWT token validation with Entra ID

**Key components:**
- `EntraIDValidator` class:
  - Fetches JWKS (public keys) from `https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys`
  - Caches JWKS with `@lru_cache` (1-hour TTL)
  - Validates JWT signature using RS256
  - Verifies claims: `iss`, `aud`, `exp`, `nbf`
  - Returns decoded user claims (email, name, etc.)

- `get_current_user()` dependency:
  - FastAPI dependency for token validation
  - Extracts token from `Authorization: Bearer <token>` header
  - Returns user claims or raises HTTPException(401)

**Dependencies needed:**
```python
from jose import jwt, JWTError, jwk
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer
import requests
```

**Error handling:**
- Invalid signature → 401 Unauthorized
- Expired token → 401 Unauthorized
- Wrong audience/issuer → 401 Unauthorized
- Missing Authorization header → 401 Unauthorized

### File 2: `src/config.py` (UPDATE - Add Config Validation)

**Changes:**
- Add `entra_audience` field (optional, defaults to `client_id`)
- Add `model_post_init` method to validate auth config:
  ```python
  def model_post_init(self, __context):
      if self.enable_auth:
          if not self.entra_tenant_id or not self.entra_client_id:
              raise ValueError(
                  "ENTRA_TENANT_ID and ENTRA_CLIENT_ID required when ENABLE_AUTH=true"
              )
  ```

**Lines to modify:** Add after line 59

### File 3: `src/server.py` (UPDATE - Add Auth Middleware)

**Changes:**

1. **Add imports** (after line 15):
```python
from .auth import EntraIDValidator
```

2. **Create `configure_auth_middleware()` function** (after `configure_cors` function):
```python
def configure_auth_middleware(app: FastAPI):
    """Configure authentication middleware if enabled."""
    if not settings.enable_auth:
        logger.info("authentication_disabled")
        return

    logger.info("authentication_enabled",
                tenant_id=settings.entra_tenant_id,
                client_id=settings.entra_client_id)

    # Initialize and test validator
    try:
        validator = EntraIDValidator()
        validator.get_signing_keys()  # Test JWKS connectivity
        logger.info("entra_id_validator_initialized")
    except Exception as e:
        logger.error("failed_to_initialize_auth", error=str(e))
        raise

    # Add middleware
    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        # Skip /health endpoint
        if request.url.path == "/health":
            return await call_next(request)

        # Skip if auth disabled
        if not settings.enable_auth:
            return await call_next(request)

        # Extract and validate token
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            logger.warning("missing_auth_header", path=request.url.path)
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid Authorization header"}
            )

        token = auth_header.split(" ")[1]

        try:
            user_claims = validator.validate_token(token)
            request.state.user = user_claims

            logger.info("authenticated_request",
                       user=user_claims.get("preferred_username", "unknown"),
                       path=request.url.path)

            return await call_next(request)

        except HTTPException as e:
            logger.warning("authentication_failed",
                          path=request.url.path,
                          reason=str(e.detail))
            return JSONResponse(status_code=401, content={"detail": str(e.detail)})
        except Exception as e:
            logger.error("authentication_error", error=str(e))
            return JSONResponse(status_code=500, content={"detail": "Authentication error"})
```

3. **Update startup** (lines 217-220):
```python
try:
    if hasattr(mcp, 'app'):
        configure_cors(mcp.app)
        configure_auth_middleware(mcp.app)  # ADD THIS LINE
except Exception as e:
    logger.warning("middleware_configuration_warning", error=str(e))
    if settings.enable_auth:  # ADD THIS - fail if auth enabled but can't configure
        raise
```

4. **Optional: Add user context to tool logging** (lines 71-75 in `search_knowledge_base`):
```python
user_info = getattr(request.state, 'user', None) if hasattr(request, 'state') else None
logger.info("search_request",
           query=query,
           max_results=max_results,
           user=user_info.get("preferred_username") if user_info else "anonymous")
```

### File 4: `src/__main__.py` (UPDATE - Register Auth Middleware)

**Changes:**
- Line 3: Add `configure_auth_middleware` to imports
- Lines 15-19: Add auth middleware registration:
```python
try:
    if hasattr(mcp, 'app'):
        configure_cors(mcp.app)
        configure_auth_middleware(mcp.app)  # ADD THIS
except Exception as e:
    logger.warning("middleware_configuration_warning", error=str(e))
    if settings.enable_auth:  # ADD THIS
        raise
```

### File 5: `requirements.txt` (UPDATE - Add Dependencies)

**Add these lines:**
```
# Microsoft Entra ID Authentication
python-jose[cryptography]>=3.3.0
PyJWT>=2.8.0
cryptography>=42.0.0
requests>=2.31.0
```

**Note:** Using lightweight libraries instead of `fastapi-microsoft-identity` for more control and fewer dependencies.

### File 6: `.env.example` (UPDATE - Document Auth Variables)

**Update lines 35-39:**
```bash
# Authentication Settings (Microsoft Entra ID)
ENABLE_AUTH=false
AUTH_PROVIDER=entra

# Required when ENABLE_AUTH=true:
# Get these from Azure Portal → Microsoft Entra ID → App Registrations
ENTRA_TENANT_ID=your-tenant-id-guid-here
ENTRA_CLIENT_ID=your-client-id-guid-here

# Optional - defaults to ENTRA_CLIENT_ID if not set:
# ENTRA_AUDIENCE=api://your-client-id
```

### File 7: `tests/test_auth.py` (NEW FILE - Comprehensive Tests)

**Test coverage:**
1. `TestEntraIDValidator`:
   - Valid token validation
   - Expired token rejection
   - Invalid signature rejection
   - Wrong audience rejection
   - Wrong issuer rejection
   - JWKS caching behavior

2. `TestAuthMiddleware`:
   - Health endpoint bypasses auth
   - Protected endpoints require token
   - Missing token returns 401
   - Invalid token returns 401
   - Valid token grants access
   - User context added to request.state

3. `TestConfigValidation`:
   - Auth disabled by default
   - Missing tenant_id raises error when auth enabled
   - Missing client_id raises error when auth enabled

**Use `python-jose` to create test JWT tokens for validation testing.**

### File 8: `docker-compose.yml` & `docker-compose.ecr.yml` (UPDATE)

**Add environment variables:**
```yaml
environment:
  - ENABLE_AUTH=${ENABLE_AUTH:-false}
  - ENTRA_TENANT_ID=${ENTRA_TENANT_ID}
  - ENTRA_CLIENT_ID=${ENTRA_CLIENT_ID}
```

## Testing Approach

### 1. Unit Tests (pytest)

```bash
# Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Run auth tests
pytest tests/test_auth.py -v

# Run all tests with coverage
pytest --cov=src --cov-report=html
```

### 2. Manual Testing - Auth Disabled (Backward Compatibility)

```bash
# Start server without auth
ENABLE_AUTH=false python -m src

# Test health endpoint (should succeed)
curl http://localhost:8000/health

# Test MCP endpoint (should succeed without token)
curl http://localhost:8000/
```

### 3. Manual Testing - Auth Enabled

```bash
# Start server with auth
ENABLE_AUTH=true \
ENTRA_TENANT_ID=your-tenant-id \
ENTRA_CLIENT_ID=your-client-id \
python -m src

# Test health endpoint (should succeed without token)
curl http://localhost:8000/health

# Test protected endpoint without token (should get 401)
curl http://localhost:8000/

# Get real token from Azure AD
az login
TOKEN=$(az account get-access-token --resource your-client-id --query accessToken -o tsv)

# Test with valid token (should succeed)
curl http://localhost:8000/ \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Integration Testing with Claude.ai

**Configure connector in Claude.ai:**
1. Go to Claude.ai → Settings → Integrations
2. Add custom connector
3. Server URL: `https://your-server-url/sse`
4. Advanced settings:
   - OAuth Client ID: `your-client-id`
   - OAuth Client Secret: `your-client-secret` (from Azure AD)
   - Authorization URL: `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize`
   - Token URL: `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`
   - Scopes: `User.Read offline_access`
5. Save and authenticate
6. Test searching knowledge base through Claude

## Verification Steps

### After Implementation:

1. **Configuration validation works:**
   - Starting with `ENABLE_AUTH=true` but missing tenant/client IDs should fail with clear error

2. **Health endpoint always accessible:**
   - `/health` returns 200 even when auth is enabled without token

3. **Protected endpoints require auth:**
   - MCP endpoints return 401 without valid token when auth enabled
   - MCP endpoints succeed with valid Azure AD token

4. **Token validation is robust:**
   - Expired tokens rejected
   - Tokens from wrong tenant rejected
   - Invalid signatures rejected
   - Valid tokens accepted

5. **User context logged:**
   - Check logs for `authenticated_request` events with user email
   - Tool invocations log user identity

6. **JWKS caching works:**
   - First request fetches JWKS (check logs)
   - Subsequent requests use cached keys (faster)
   - Keys refresh after TTL expires

7. **Claude.ai integration works:**
   - Users can add connector and complete OAuth flow
   - Token refresh handled automatically by Claude
   - MCP tools accessible through authenticated connection

## Security Considerations

1. **Always use HTTPS in production** - JWT tokens must not be sent over HTTP
2. **JWKS caching** - 1-hour cache prevents excessive requests to Azure AD
3. **Token expiration** - Respect `exp` claim, don't extend token lifetime
4. **Health endpoint exception** - Load balancers need unauthenticated access
5. **User identity logging** - Log user claims for audit trail (but never log full tokens)
6. **Secrets management** - Never commit tenant/client IDs to git; use environment variables
7. **CORS configuration** - Keep restricted to claude.ai domains with `allow_credentials=True`

## Implementation Sequence

**Phase 1: Core Auth (Priority 1)**
1. Add dependencies to `requirements.txt`
2. Create `src/auth.py` with `EntraIDValidator`
3. Update `src/config.py` with validation
4. Add unit tests

**Phase 2: Middleware Integration (Priority 1)**
5. Add `configure_auth_middleware()` to `src/server.py`
6. Update `src/__main__.py`
7. Test with mock tokens locally

**Phase 3: Testing & Documentation (Priority 2)**
8. Complete test suite in `tests/test_auth.py`
9. Update `.env.example`
10. Update Docker configurations
11. Manual testing with Azure CLI tokens

**Phase 4: Production Deployment (Priority 3)**
12. Create Azure AD App Registration
13. Deploy to EC2 with auth enabled
14. Configure Claude.ai connector with OAuth settings
15. End-to-end testing with real users

## Critical Files Summary

- **`src/auth.py`** - NEW - JWT validation logic (400-500 lines)
- **`src/server.py`** - UPDATE - Middleware registration (~60 lines added)
- **`src/config.py`** - UPDATE - Config validation (~10 lines added)
- **`src/__main__.py`** - UPDATE - Middleware call (~3 lines added)
- **`requirements.txt`** - UPDATE - Add 4 auth dependencies
- **`.env.example`** - UPDATE - Document auth variables
- **`tests/test_auth.py`** - NEW - Comprehensive test suite (300-400 lines)
- **`docker-compose.yml`** - UPDATE - Add 3 environment variables
- **`docker-compose.ecr.yml`** - UPDATE - Add 3 environment variables

## Expected Outcome

After implementation:
- ✅ Users authenticate with Azure AD through Claude.ai's OAuth flow
- ✅ Server validates bearer tokens on all requests (except `/health`)
- ✅ User identity captured for audit logging
- ✅ Backward compatible (auth disabled by default)
- ✅ Production-ready with proper error handling
- ✅ Comprehensive test coverage
- ✅ Clear documentation for Azure AD setup and Claude.ai configuration
