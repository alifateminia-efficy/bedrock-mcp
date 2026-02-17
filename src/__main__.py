"""Entry point for running the Bedrock MCP server as a module."""

from .server import mcp, logger, settings, configure_cors, configure_auth_middleware

if __name__ == "__main__":
    logger.info(
        "starting_server_from_module",
        host=settings.server_host,
        port=settings.server_port,
        kb_id=settings.bedrock_kb_id,
        region=settings.aws_region
    )

    # Configure middleware (CORS and Auth)
    try:
        if hasattr(mcp, 'app'):
            configure_cors(mcp.app)
            configure_auth_middleware(mcp.app)
    except Exception as e:
        logger.warning("middleware_configuration_warning", error=str(e))
        if settings.enable_auth:
            raise

    # Run the server
    mcp.run(
        transport="http",
        host=settings.server_host,
        port=settings.server_port
    )
