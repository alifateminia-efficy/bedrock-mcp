"""FastMCP server for AWS Bedrock Knowledge Base."""

import logging
import sys
from typing import Dict

import structlog
from fastmcp import FastMCP
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlencode
from mcp import types

from .bedrock_client import BedrockKBClient
from .config import settings
from .auth import EntraIDValidator

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

# Configure standard logging
logging.basicConfig(
    format="%(message)s",
    stream=sys.stdout,
    level=getattr(logging, settings.log_level.upper()),
)
logger = structlog.get_logger()

# Initialize FastMCP server
mcp = FastMCP("Bedrock Knowledge Base Server")

# Initialize Bedrock client
try:
    bedrock_client = BedrockKBClient()
    logger.info(
        "bedrock_client_initialized",
        kb_id=settings.bedrock_kb_id,
        region=settings.aws_region
    )
except Exception as e:
    logger.error("failed_to_initialize_bedrock_client", error=str(e))
    raise


@mcp.tool(annotations=types.ToolAnnotations(readOnlyHint=True))
def search_knowledge_base(query: str, max_results: int = 5) -> str:
    """
    Search the AWS Bedrock Knowledge Base and retrieve relevant documents.

    Args:
        query: The search query text to find relevant documents
        max_results: Maximum number of results to return (default: 5, range: 1-100)

    Returns:
        Formatted string containing document chunks with relevance scores and sources
    """
    logger.info(
        "search_request",
        query=query,
        max_results=max_results
    )

    try:
        # Validate max_results
        if max_results < 1 or max_results > 100:
            error_msg = "max_results must be between 1 and 100"
            logger.warning("invalid_max_results", max_results=max_results)
            return f"Error: {error_msg}"

        # Retrieve documents from Knowledge Base
        response = bedrock_client.retrieve(query, max_results)
        results = response.get("results", [])

        if not results:
            logger.info("no_results_found", query=query)
            return f"No results found for query: '{query}'"

        # Format results
        formatted_output = [
            f"Found {len(results)} result(s) for query: '{query}'\n"
        ]

        for idx, result in enumerate(results, 1):
            content = result.get("content", "")
            score = result.get("score", 0.0)
            source_uri = result.get("source_uri", "Unknown")

            formatted_output.append(
                f"\n--- Result {idx} (Relevance Score: {score:.4f}) ---\n"
                f"Source: {source_uri}\n"
                f"Content:\n{content}\n"
            )

        logger.info(
            "search_completed",
            query=query,
            results_count=len(results)
        )

        return "".join(formatted_output)

    except ValueError as e:
        logger.error("validation_error", error=str(e), query=query)
        return f"Validation Error: {e}"
    except PermissionError as e:
        logger.error("permission_error", error=str(e))
        return f"Permission Error: {e}"
    except RuntimeError as e:
        logger.error("runtime_error", error=str(e), query=query)
        return f"Error: {e}"
    except Exception as e:
        logger.error("unexpected_error", error=str(e), query=query)
        return f"Unexpected Error: {e}"


@mcp.tool(annotations=types.ToolAnnotations(readOnlyHint=True))
def get_knowledge_base_info() -> Dict[str, str]:
    """
    Get information about the configured AWS Bedrock Knowledge Base.

    Returns:
        Dictionary containing KB ID, region, and status information
    """
    logger.info("kb_info_request")

    try:
        kb_info = bedrock_client.get_kb_info()
        logger.info("kb_info_retrieved", kb_info=kb_info)
        return {
            "kb_id": kb_info["kb_id"],
            "region": kb_info["region"],
            "status": "configured"
        }
    except Exception as e:
        logger.error("kb_info_error", error=str(e))
        return {
            "error": str(e),
            "status": "error"
        }


# Add health check endpoint to the underlying FastAPI app
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request):
    """
    Health check endpoint for monitoring and load balancer health checks.

    Args:
        request: The incoming HTTP request

    Returns:
        JSON response with health status, KB ID, and region
    """
    logger.debug("health_check_request")

    try:
        kb_info = bedrock_client.get_kb_info()
        return JSONResponse({
            "status": "healthy",
            "kb_id": kb_info["kb_id"],
            "region": kb_info["region"],
            "service": "bedrock-mcp-http"
        })
    except Exception as e:
        logger.error("health_check_error", error=str(e))
        return JSONResponse({
            "status": "unhealthy",
            "error": str(e),
            "service": "bedrock-mcp-http"
        }, status_code=503)


@mcp.custom_route("/authorize", methods=["GET"])
async def oauth_authorize(request: Request):
    """
    OAuth2 authorization endpoint - Redirects to Azure AD login.

    Claude.ai calls this endpoint to start the OAuth flow. We proxy the request
    to Azure AD by building the authorization URL with the correct tenant ID.
    """
    logger.info("oauth_authorize_request", query_params=dict(request.query_params))

    try:
        # Extract OAuth parameters from Claude.ai
        params = dict(request.query_params)

        # Validate required parameters
        required = ["response_type", "client_id", "redirect_uri", "state"]
        missing = [p for p in required if p not in params]
        if missing:
            return JSONResponse(
                {"error": "invalid_request", "error_description": f"Missing parameters: {missing}"},
                status_code=400
            )

        # Build Azure AD authorization URL
        azure_params = {
            "response_type": params["response_type"],
            "client_id": params["client_id"],
            "redirect_uri": params["redirect_uri"],
            "state": params["state"],
            "scope": "User.Read openid profile email offline_access",  # Azure AD scopes
        }

        # Add PKCE parameters if present
        if "code_challenge" in params:
            azure_params["code_challenge"] = params["code_challenge"]
        if "code_challenge_method" in params:
            azure_params["code_challenge_method"] = params["code_challenge_method"]

        # Construct Azure AD authorization URL
        azure_auth_url = (
            f"https://login.microsoftonline.com/{settings.entra_tenant_id}/oauth2/v2.0/authorize?"
            f"{urlencode(azure_params)}"
        )

        logger.info("redirecting_to_azure_ad", url=azure_auth_url)

        # Redirect user to Azure AD login
        return RedirectResponse(url=azure_auth_url, status_code=302)

    except Exception as e:
        logger.error("oauth_authorize_error", error=str(e))
        return JSONResponse(
            {"error": "server_error", "error_description": str(e)},
            status_code=500
        )


@mcp.custom_route("/token", methods=["POST"])
async def oauth_token(request: Request):
    """
    OAuth2 token endpoint - Exchanges authorization code for access token.

    Claude.ai calls this endpoint with the authorization code. We forward the
    request to Azure AD's token endpoint and return the access token.
    """
    logger.info("oauth_token_request")

    try:
        # Parse form data from Claude.ai
        form_data = await request.form()
        form_dict = dict(form_data)

        logger.debug("token_request_data", grant_type=form_dict.get("grant_type"))

        # Validate grant type
        if form_dict.get("grant_type") != "authorization_code":
            return JSONResponse(
                {"error": "unsupported_grant_type"},
                status_code=400
            )

        # Forward to Azure AD token endpoint
        azure_token_url = f"https://login.microsoftonline.com/{settings.entra_tenant_id}/oauth2/v2.0/token"

        # Prepare token request data
        token_data = {
            "grant_type": "authorization_code",
            "code": form_dict.get("code"),
            "redirect_uri": form_dict.get("redirect_uri"),
            "client_id": form_dict.get("client_id"),
            "client_secret": form_dict.get("client_secret"),
            "code_verifier": form_dict.get("code_verifier"),
            "scope": "User.Read openid profile email offline_access",
        }

        # Remove None values
        token_data = {k: v for k, v in token_data.items() if v is not None}

        logger.info("exchanging_code_with_azure_ad")

        # Exchange code for token with Azure AD
        import requests
        response = requests.post(
            azure_token_url,
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10
        )

        # Return Azure AD response to Claude.ai (proxy)
        if response.status_code == 200:
            logger.info("token_exchange_successful")
            return JSONResponse(response.json(), status_code=200)
        else:
            logger.error("token_exchange_failed", status=response.status_code, error=response.text)
            return JSONResponse(response.json(), status_code=response.status_code)

    except Exception as e:
        logger.error("oauth_token_error", error=str(e))
        return JSONResponse(
            {"error": "server_error", "error_description": str(e)},
            status_code=500
        )


# Configure CORS for claude.ai
def configure_cors(app: FastAPI):
    """Configure CORS middleware for the FastAPI app."""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "https://claude.ai",
            "https://*.claude.ai",
            "http://localhost:*",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def configure_auth_middleware(app: FastAPI):
    """Configure authentication middleware if enabled."""
    if not settings.enable_auth:
        logger.info("authentication_disabled")
        return

    logger.info(
        "authentication_enabled",
        tenant_id=settings.entra_tenant_id,
        client_id=settings.entra_client_id
    )

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

            logger.info(
                "authenticated_request",
                user=user_claims.get("preferred_username", "unknown"),
                path=request.url.path
            )

            return await call_next(request)

        except Exception as e:
            # HTTPException or any other error
            error_detail = getattr(e, 'detail', str(e))
            logger.warning(
                "authentication_failed",
                path=request.url.path,
                reason=error_detail
            )
            return JSONResponse(
                status_code=401,
                content={"detail": error_detail}
            )


if __name__ == "__main__":
    logger.info(
        "starting_server",
        host=settings.server_host,
        port=settings.server_port,
        kb_id=settings.bedrock_kb_id,
        region=settings.aws_region,
        log_level=settings.log_level
    )

    # Get the underlying FastAPI app and configure CORS and Auth
    # Note: FastMCP should expose the FastAPI app instance
    # If not directly accessible, CORS might need to be configured differently
    try:
        if hasattr(mcp, 'app'):
            configure_cors(mcp.app)
            configure_auth_middleware(mcp.app)
    except Exception as e:
        logger.warning("middleware_configuration_warning", error=str(e))
        if settings.enable_auth:
            raise

    # Run the server with HTTP transport
    mcp.run(
        transport="http",
        host=settings.server_host,
        port=settings.server_port
    )
