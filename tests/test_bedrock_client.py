"""Unit tests for BedrockKBClient."""

import pytest
from botocore.exceptions import ClientError
from unittest.mock import Mock, patch, MagicMock

from src.bedrock_client import BedrockKBClient


@pytest.fixture
def mock_boto3_client():
    """Create a mock boto3 client."""
    with patch("src.bedrock_client.boto3.client") as mock_client:
        yield mock_client


@pytest.fixture
def bedrock_client(mock_boto3_client):
    """Create a BedrockKBClient instance with mocked boto3 client."""
    with patch("src.bedrock_client.settings") as mock_settings:
        mock_settings.bedrock_kb_id = "test-kb-id"
        mock_settings.aws_region = "eu-west-1"
        client = BedrockKBClient()
        return client


class TestBedrockKBClientInitialization:
    """Tests for BedrockKBClient initialization."""

    def test_initialization_success(self, mock_boto3_client):
        """Test successful client initialization."""
        with patch("src.bedrock_client.settings") as mock_settings:
            mock_settings.bedrock_kb_id = "test-kb-id"
            mock_settings.aws_region = "eu-west-1"

            client = BedrockKBClient()

            assert client.kb_id == "test-kb-id"
            mock_boto3_client.assert_called_once_with(
                "bedrock-agent-runtime",
                region_name="eu-west-1"
            )


class TestRetrieve:
    """Tests for the retrieve method."""

    def test_retrieve_success(self, bedrock_client):
        """Test successful document retrieval."""
        # Mock response
        mock_response = {
            "retrievalResults": [
                {
                    "content": {"text": "Test content 1"},
                    "score": 0.95,
                    "metadata": {"source": "test1.pdf"},
                    "location": {"s3Location": {"uri": "s3://bucket/test1.pdf"}}
                },
                {
                    "content": {"text": "Test content 2"},
                    "score": 0.85,
                    "metadata": {"source": "test2.pdf"},
                    "location": {"webLocation": {"url": "https://example.com/test2"}}
                }
            ]
        }
        bedrock_client.client.retrieve = Mock(return_value=mock_response)

        # Execute
        result = bedrock_client.retrieve("test query", max_results=5)

        # Assert
        assert result["count"] == 2
        assert result["query"] == "test query"
        assert len(result["results"]) == 2
        assert result["results"][0]["content"] == "Test content 1"
        assert result["results"][0]["score"] == 0.95
        assert result["results"][0]["source_uri"] == "s3://bucket/test1.pdf"
        assert result["results"][1]["source_uri"] == "https://example.com/test2"

    def test_retrieve_empty_query(self, bedrock_client):
        """Test retrieval with empty query raises ValueError."""
        with pytest.raises(ValueError, match="Query cannot be empty"):
            bedrock_client.retrieve("")

    def test_retrieve_invalid_max_results(self, bedrock_client):
        """Test retrieval with invalid max_results raises ValueError."""
        with pytest.raises(ValueError, match="max_results must be between 1 and 100"):
            bedrock_client.retrieve("test query", max_results=0)

        with pytest.raises(ValueError, match="max_results must be between 1 and 100"):
            bedrock_client.retrieve("test query", max_results=101)

    def test_retrieve_kb_not_found(self, bedrock_client):
        """Test retrieval with non-existent Knowledge Base."""
        error_response = {
            "Error": {
                "Code": "ResourceNotFoundException",
                "Message": "Knowledge Base not found"
            }
        }
        bedrock_client.client.retrieve = Mock(
            side_effect=ClientError(error_response, "retrieve")
        )

        with pytest.raises(ValueError, match="Knowledge Base .* not found"):
            bedrock_client.retrieve("test query")

    def test_retrieve_access_denied(self, bedrock_client):
        """Test retrieval with access denied error."""
        error_response = {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "Access denied"
            }
        }
        bedrock_client.client.retrieve = Mock(
            side_effect=ClientError(error_response, "retrieve")
        )

        with pytest.raises(PermissionError, match="Access denied"):
            bedrock_client.retrieve("test query")

    def test_retrieve_throttling(self, bedrock_client):
        """Test retrieval with throttling error."""
        error_response = {
            "Error": {
                "Code": "ThrottlingException",
                "Message": "Rate exceeded"
            }
        }
        bedrock_client.client.retrieve = Mock(
            side_effect=ClientError(error_response, "retrieve")
        )

        with pytest.raises(RuntimeError, match="Request throttled"):
            bedrock_client.retrieve("test query")

    def test_retrieve_validation_error(self, bedrock_client):
        """Test retrieval with validation error."""
        error_response = {
            "Error": {
                "Code": "ValidationException",
                "Message": "Invalid parameters"
            }
        }
        bedrock_client.client.retrieve = Mock(
            side_effect=ClientError(error_response, "retrieve")
        )

        with pytest.raises(ValueError, match="Invalid request"):
            bedrock_client.retrieve("test query")


class TestGetKBInfo:
    """Tests for the get_kb_info method."""

    def test_get_kb_info(self, bedrock_client):
        """Test getting Knowledge Base info."""
        with patch("src.bedrock_client.settings") as mock_settings:
            mock_settings.bedrock_kb_id = "test-kb-id"
            mock_settings.aws_region = "eu-west-1"

            info = bedrock_client.get_kb_info()

            assert info["kb_id"] == "test-kb-id"
            assert info["region"] == "eu-west-1"


class TestFormatResults:
    """Tests for the format_results method."""

    def test_format_results_success(self, bedrock_client):
        """Test successful results formatting."""
        results = [
            {
                "content": "Test content 1",
                "score": 0.95,
                "source_uri": "s3://bucket/test1.pdf"
            },
            {
                "content": "Test content 2",
                "score": 0.85,
                "source_uri": "https://example.com/test2"
            }
        ]

        formatted = bedrock_client.format_results(results)

        assert "Result 1 (Relevance: 0.950)" in formatted
        assert "Test content 1" in formatted
        assert "s3://bucket/test1.pdf" in formatted
        assert "Result 2 (Relevance: 0.850)" in formatted
        assert "Test content 2" in formatted

    def test_format_results_empty(self, bedrock_client):
        """Test formatting empty results."""
        formatted = bedrock_client.format_results([])
        assert formatted == "No results found."
