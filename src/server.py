"""FastMCP server for AWS Bedrock Knowledge Base."""

import logging
import sys
from typing import Dict

import structlog
from fastmcp import FastMCP
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from mcp import types

from .bedrock_client import BedrockKBClient
from .config import settings

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


if __name__ == "__main__":
    logger.info(
        "starting_server",
        host=settings.server_host,
        port=settings.server_port,
        kb_id=settings.bedrock_kb_id,
        region=settings.aws_region,
        log_level=settings.log_level
    )

    # Get the underlying FastAPI app and configure CORS
    # Note: FastMCP should expose the FastAPI app instance
    # If not directly accessible, CORS might need to be configured differently
    try:
        if hasattr(mcp, 'app'):
            configure_cors(mcp.app)
    except Exception as e:
        logger.warning("cors_configuration_warning", error=str(e))

    # Run the server with HTTP transport
    mcp.run(
        transport="http",
        host=settings.server_host,
        port=settings.server_port
    )
