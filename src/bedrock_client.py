"""AWS Bedrock Knowledge Base client wrapper."""

import logging
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .config import settings

logger = logging.getLogger(__name__)


class BedrockKBClient:
    """Client for interacting with AWS Bedrock Knowledge Base."""

    def __init__(self):
        """Initialize the Bedrock Knowledge Base client."""
        try:
            self.client = boto3.client(
                "bedrock-agent-runtime",
                region_name=settings.aws_region
            )
            self.kb_id = settings.bedrock_kb_id
            logger.info(
                f"Initialized Bedrock KB client for KB: {self.kb_id} in region: {settings.aws_region}"
            )
        except Exception as e:
            logger.error(f"Failed to initialize Bedrock KB client: {e}")
            raise

    def retrieve(
        self,
        query: str,
        max_results: int = 5,
        metadata_filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Retrieve documents from the Knowledge Base.

        Args:
            query: The search query text
            max_results: Maximum number of results to return (default: 5)
            metadata_filters: Optional metadata filters for the query

        Returns:
            Dictionary containing:
                - results: List of document chunks with relevance scores
                - count: Number of results returned
                - query: Original query text

        Raises:
            ValueError: If query is empty or max_results is invalid
            ClientError: If AWS API call fails
        """
        # Validate input
        if not query or not query.strip():
            raise ValueError("Query cannot be empty")

        if max_results < 1 or max_results > 100:
            raise ValueError("max_results must be between 1 and 100")

        logger.info(f"Retrieving documents for query: '{query}' (max_results: {max_results})")

        try:
            # Prepare request parameters
            request_params = {
                "knowledgeBaseId": self.kb_id,
                "retrievalQuery": {
                    "text": query.strip()
                },
                "retrievalConfiguration": {
                    "vectorSearchConfiguration": {
                        "numberOfResults": max_results
                    }
                }
            }

            # Add metadata filters if provided
            if metadata_filters:
                request_params["retrievalConfiguration"]["vectorSearchConfiguration"]["filter"] = metadata_filters

            # Make the API call
            response = self.client.retrieve(**request_params)

            # Parse and format the response
            results = []
            for item in response.get("retrievalResults", []):
                result = {
                    "content": item.get("content", {}).get("text", ""),
                    "score": item.get("score", 0.0),
                    "metadata": item.get("metadata", {}),
                    "location": item.get("location", {})
                }

                # Extract source URI if available
                if "s3Location" in item.get("location", {}):
                    result["source_uri"] = item["location"]["s3Location"].get("uri", "")
                elif "webLocation" in item.get("location", {}):
                    result["source_uri"] = item["location"]["webLocation"].get("url", "")
                else:
                    result["source_uri"] = None

                results.append(result)

            logger.info(f"Successfully retrieved {len(results)} documents")

            return {
                "results": results,
                "count": len(results),
                "query": query
            }

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = e.response.get("Error", {}).get("Message", str(e))

            # Handle specific error cases
            if error_code == "ResourceNotFoundException":
                logger.error(f"Knowledge Base not found: {self.kb_id}")
                raise ValueError(f"Knowledge Base '{self.kb_id}' not found") from e
            elif error_code == "AccessDeniedException":
                logger.error(f"Access denied to Knowledge Base: {self.kb_id}")
                raise PermissionError(
                    f"Access denied to Knowledge Base '{self.kb_id}'. Check IAM permissions."
                ) from e
            elif error_code == "ThrottlingException":
                logger.warning(f"Request throttled for KB: {self.kb_id}")
                raise RuntimeError("Request throttled. Please try again later.") from e
            elif error_code == "ValidationException":
                logger.error(f"Invalid request parameters: {error_message}")
                raise ValueError(f"Invalid request: {error_message}") from e
            else:
                logger.error(f"AWS API error ({error_code}): {error_message}")
                raise RuntimeError(f"AWS API error: {error_message}") from e

        except BotoCoreError as e:
            logger.error(f"Boto3 error: {e}")
            raise RuntimeError(f"AWS SDK error: {e}") from e

        except Exception as e:
            logger.error(f"Unexpected error during retrieval: {e}")
            raise RuntimeError(f"Unexpected error: {e}") from e

    def get_kb_info(self) -> Dict[str, str]:
        """
        Get information about the configured Knowledge Base.

        Returns:
            Dictionary containing KB ID and region
        """
        return {
            "kb_id": self.kb_id,
            "region": settings.aws_region
        }

    def format_results(self, results: List[Dict[str, Any]]) -> str:
        """
        Format retrieval results as readable text.

        Args:
            results: List of result dictionaries from retrieve()

        Returns:
            Formatted string representation of results
        """
        if not results:
            return "No results found."

        formatted = []
        for idx, result in enumerate(results, 1):
            content = result.get("content", "")
            score = result.get("score", 0.0)
            source_uri = result.get("source_uri", "Unknown")

            formatted.append(
                f"Result {idx} (Relevance: {score:.3f}):\n"
                f"Source: {source_uri}\n"
                f"Content: {content}\n"
            )

        return "\n".join(formatted)
