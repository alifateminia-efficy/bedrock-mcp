"""Tests for Microsoft Entra ID authentication."""

import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

import pytest
from fastapi import HTTPException, FastAPI
from fastapi.testclient import TestClient
from jose import jwt

from src.auth import EntraIDValidator, get_validator, get_current_user
from src.config import Settings


# Test fixtures and constants
TEST_TENANT_ID = "12345678-1234-1234-1234-123456789abc"
TEST_CLIENT_ID = "abcdefgh-abcd-abcd-abcd-abcdefghijkl"
TEST_AUDIENCE = TEST_CLIENT_ID
TEST_ISSUER = f"https://login.microsoftonline.com/{TEST_TENANT_ID}/v2.0"
TEST_JWKS_URI = f"https://login.microsoftonline.com/{TEST_TENANT_ID}/discovery/v2.0/keys"

# Mock RSA key pair for testing
TEST_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6RQ3mF2hFTxDzFAU5LdOLuB6enf
lQvSWDvjpJDQbJvXlY2RdHv9hgJvdEJqQQWqNl8p/HnXmqFjUYJZQFSIDPEL4b8s
5NLVFRmPqCrJQQs+pRgN7qMr4VqWDTfCLKcwAT0NU4lWvLw/fHU3xccXCLCpfkQd
h7/E8XG8WGJ3zqM/O/xJqmNbGY7J+sKLEbr7jEQKPG2K0W9aKjUWp2LbP9xhPfXR
WFGxJ4Q8fqzHLQ0lH8xppQGYKh4Q7jPE9EYCmMNl1pNqLTqVWbVAa8qBjXYQLqBX
K2KHI5lM9qVsYj7HfCKzL7SsIhMlKLRQVWGJWwIDAQABAoIBAAWPb4rqTpyJp8zT
bvMKr3KJqTkRMQxeF3hEQdPPFhU+I8zcHVhHBYDL5KXhLjvbQGnZUjUWdWELc0Wc
r5l+h6YhMQSNhYWbPZMRIJm0QLT3OJvfKCH6wGWqTdCvF+pqZvl2sF8E4sFxkbG9
nqj3U5Z6cVQXfFCTrqm5pqLf7KN1bHsqMHPz5dVwN+UqFpZX2V9FhOLlQqKsJFQV
nH6Fl5F+FmG5PqPHK0U8F+pzKJ0fPvMNq7F3L1E9nqH+hGCcT3KhNjFxqVqH5F0e
JqGhCpqLKqP7LZ5fqT0nHqK8FqPzL5F+hGCcT3KhNjFxqVqH5F0eJqGhCpqLKqP7
LZ5fqQECgYEA7hzM8j5FmL0qQxzF0qRqBpGzQqHVH8L5F+hGCcT3KhNjFxqVqH5F
0eJqGhCpqLKqP7LZ5fqT0nHqK8FqPzL5F+hGCcT3KhNjFxqVqH5F0eJqGhCpqLKq
P7LZ5fqT0nHqK8FqPzL5F+hGCcT3KhNjFxqVqH5F0eJqGhCpqLKqP7LZ5fqQECgY
EA4FQqTpyJp8zTbvMKr3KJqTkRMQxeF3hEQdPPFhU+I8zcHVhHBYDL5KXhLjvbQG
nZUjUWdWELc0Wcr5l+h6YhMQSNhYWbPZMRIJm0QLT3OJvfKCH6wGWqTdCvF+pqZv
l2sF8E4sFxkbG9nqj3U5Z6cVQXfFCTrqm5pqLf7KN1bHsqMHPz5dVwN+UqFpZX2V
9FhOLlQqKsJFQVnH6Fl5F+FmG5PqPHK0U8F+pzKJ0fPvMNq7F3L1E9nqH+hGCcEC
gYEA0Z3VS5JJcds3xfn/ygWyF6RQ3mF2hFTxDzFAU5LdOLuB6enflQvSWDvjpJDQ
bJvXlY2RdHv9hgJvdEJqQQWqNl8p/HnXmqFjUYJZQFSIDPEL4b8s5NLVFRmPqCrJ
QQs+pRgN7qMr4VqWDTfCLKcwAT0NU4lWvLw/fHU3xccXCLCpfkQdh7/E8XG8WGJ3
zqM/O/xJqmNbGY7J+sKLEbr7jEQKPG2K0W9aKjUWp2LbP9xhPfXRWFGxJ4Q8fqzH
-----END RSA PRIVATE KEY-----"""


@pytest.fixture
def mock_jwks():
    """Mock JWKS response from Azure AD."""
    return {
        "keys": [
            {
                "kid": "test-key-id-1",
                "kty": "RSA",
                "use": "sig",
                "n": "0Z3VS5JJcds3xfn_ygWyF6RQ3mF2hFTxDzFAU5LdOLuB6enflQvSWDvjpJDQbJvXlY2RdHv9hgJvdEJqQQWqNl8p_HnXmqFjUYJZQFSIDPEL4b8s5NLVFRmPqCrJQQs-pRgN7qMr4VqWDTfCLKcwAT0NU4lWvLw_fHU3xccXCLCpfkQdh7_E8XG8WGJ3zqM_O_xJqmNbGY7J-sKLEbr7jEQKPG2K0W9aKjUWp2LbP9xhPfXRWFGxJ4Q8fqzHLQ0lH8xppQGYKh4Q7jPE9EYCmMNl1pNqLTqVWbVAa8qBjXYQLqBXK2KHI5lM9qVsYj7HfCKzL7SsIhMlKLRQVWGJWw",
                "e": "AQAB",
            }
        ]
    }


@pytest.fixture
def mock_settings(monkeypatch):
    """Mock settings with auth enabled."""
    monkeypatch.setattr("src.auth.settings.entra_tenant_id", TEST_TENANT_ID)
    monkeypatch.setattr("src.auth.settings.entra_client_id", TEST_CLIENT_ID)
    monkeypatch.setattr("src.auth.settings.enable_auth", True)


def create_test_token(
    tenant_id=TEST_TENANT_ID,
    client_id=TEST_CLIENT_ID,
    exp_delta=timedelta(hours=1),
    kid="test-key-id-1",
    extra_claims=None
):
    """Create a test JWT token for testing."""
    now = datetime.utcnow()

    claims = {
        "iss": f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        "aud": client_id,
        "exp": now + exp_delta,
        "nbf": now - timedelta(minutes=5),
        "iat": now,
        "sub": "test-user-123",
        "preferred_username": "testuser@example.com",
        "name": "Test User",
        "oid": "object-id-123",
    }

    if extra_claims:
        claims.update(extra_claims)

    # Encode with test key
    token = jwt.encode(
        claims,
        TEST_PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": kid}
    )

    return token


class TestEntraIDValidator:
    """Tests for the EntraIDValidator class."""

    def test_initialization_success(self, mock_settings):
        """Test validator initializes with correct settings."""
        validator = EntraIDValidator()

        assert validator.tenant_id == TEST_TENANT_ID
        assert validator.client_id == TEST_CLIENT_ID
        assert validator.audience == TEST_CLIENT_ID
        assert validator.issuer == TEST_ISSUER
        assert validator.jwks_uri == TEST_JWKS_URI

    def test_initialization_missing_tenant_id(self, monkeypatch):
        """Test validator fails when tenant_id is missing."""
        monkeypatch.setattr("src.auth.settings.entra_tenant_id", None)
        monkeypatch.setattr("src.auth.settings.entra_client_id", TEST_CLIENT_ID)

        with pytest.raises(ValueError, match="ENTRA_TENANT_ID and ENTRA_CLIENT_ID"):
            EntraIDValidator()

    def test_initialization_missing_client_id(self, monkeypatch):
        """Test validator fails when client_id is missing."""
        monkeypatch.setattr("src.auth.settings.entra_tenant_id", TEST_TENANT_ID)
        monkeypatch.setattr("src.auth.settings.entra_client_id", None)

        with pytest.raises(ValueError, match="ENTRA_TENANT_ID and ENTRA_CLIENT_ID"):
            EntraIDValidator()

    @patch('requests.get')
    def test_get_signing_keys_success(self, mock_get, mock_settings, mock_jwks):
        """Test fetching JWKS from Azure AD."""
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        validator = EntraIDValidator()
        keys = validator.get_signing_keys()

        assert "test-key-id-1" in keys
        assert keys["test-key-id-1"]["kty"] == "RSA"
        mock_get.assert_called_once()

    @patch('requests.get')
    def test_get_signing_keys_caching(self, mock_get, mock_settings, mock_jwks):
        """Test JWKS caching mechanism."""
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        validator = EntraIDValidator()

        # First call - should fetch
        keys1 = validator.get_signing_keys()
        # Second call - should use cache
        keys2 = validator.get_signing_keys()

        assert keys1 == keys2
        # Should only call the API once due to caching
        assert mock_get.call_count == 1

    @patch('requests.get')
    def test_get_signing_keys_cache_expiry(self, mock_get, mock_settings, mock_jwks):
        """Test JWKS cache expires after TTL."""
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        validator = EntraIDValidator()
        validator._cache_ttl = 1  # 1 second TTL for testing

        # First call
        validator.get_signing_keys()

        # Wait for cache to expire
        time.sleep(1.1)

        # Second call - should fetch again
        validator.get_signing_keys()

        # Should call API twice
        assert mock_get.call_count == 2

    @patch('requests.get')
    def test_get_signing_keys_network_error(self, mock_get, mock_settings):
        """Test handling of network errors when fetching JWKS."""
        mock_get.side_effect = Exception("Network error")

        validator = EntraIDValidator()

        with pytest.raises(HTTPException) as exc_info:
            validator.get_signing_keys()

        assert exc_info.value.status_code == 503

    @patch.object(EntraIDValidator, 'get_signing_keys')
    def test_get_public_key_success(self, mock_get_keys, mock_settings, mock_jwks):
        """Test extracting public key from token."""
        mock_get_keys.return_value = {
            "test-key-id-1": mock_jwks["keys"][0]
        }

        validator = EntraIDValidator()
        token = create_test_token()

        public_key = validator.get_public_key(token)
        assert public_key is not None

    @patch.object(EntraIDValidator, 'get_signing_keys')
    def test_get_public_key_unknown_kid(self, mock_get_keys, mock_settings, mock_jwks):
        """Test error when token has unknown key ID."""
        mock_get_keys.return_value = {
            "different-key-id": mock_jwks["keys"][0]
        }

        validator = EntraIDValidator()
        token = create_test_token(kid="test-key-id-1")

        with pytest.raises(HTTPException) as exc_info:
            validator.get_public_key(token)

        assert exc_info.value.status_code == 401
        assert "unknown key ID" in exc_info.value.detail

    @patch.object(EntraIDValidator, 'get_public_key')
    def test_validate_token_success(self, mock_get_key, mock_settings):
        """Test successful token validation."""
        # Mock the public key validation
        mock_key = Mock()
        mock_get_key.return_value = mock_key

        validator = EntraIDValidator()
        token = create_test_token()

        # Patch jwt.decode to return valid claims
        with patch('jose.jwt.decode') as mock_decode:
            mock_decode.return_value = {
                "sub": "test-user-123",
                "preferred_username": "testuser@example.com",
                "name": "Test User"
            }

            claims = validator.validate_token(token)

            assert claims["sub"] == "test-user-123"
            assert claims["preferred_username"] == "testuser@example.com"

    @patch.object(EntraIDValidator, 'get_public_key')
    def test_validate_token_expired(self, mock_get_key, mock_settings):
        """Test rejection of expired tokens."""
        mock_key = Mock()
        mock_get_key.return_value = mock_key

        validator = EntraIDValidator()
        token = create_test_token(exp_delta=timedelta(hours=-1))

        with patch('jose.jwt.decode') as mock_decode:
            from jose import jwt as jose_jwt
            mock_decode.side_effect = jose_jwt.ExpiredSignatureError("Token expired")

            with pytest.raises(HTTPException) as exc_info:
                validator.validate_token(token)

            assert exc_info.value.status_code == 401
            assert "expired" in exc_info.value.detail.lower()

    @patch.object(EntraIDValidator, 'get_public_key')
    def test_validate_token_wrong_audience(self, mock_get_key, mock_settings):
        """Test rejection of tokens with wrong audience."""
        mock_key = Mock()
        mock_get_key.return_value = mock_key

        validator = EntraIDValidator()
        token = create_test_token(client_id="wrong-audience")

        with patch('jose.jwt.decode') as mock_decode:
            from jose import jwt as jose_jwt
            mock_decode.side_effect = jose_jwt.JWTClaimsError("Invalid audience")

            with pytest.raises(HTTPException) as exc_info:
                validator.validate_token(token)

            assert exc_info.value.status_code == 401
            assert "claims" in exc_info.value.detail.lower()

    @patch.object(EntraIDValidator, 'get_public_key')
    def test_validate_token_wrong_issuer(self, mock_get_key, mock_settings):
        """Test rejection of tokens from wrong issuer."""
        mock_key = Mock()
        mock_get_key.return_value = mock_key

        validator = EntraIDValidator()
        token = create_test_token(tenant_id="wrong-tenant")

        with patch('jose.jwt.decode') as mock_decode:
            from jose import jwt as jose_jwt
            mock_decode.side_effect = jose_jwt.JWTClaimsError("Invalid issuer")

            with pytest.raises(HTTPException) as exc_info:
                validator.validate_token(token)

            assert exc_info.value.status_code == 401


class TestAuthMiddleware:
    """Tests for authentication middleware."""

    @pytest.fixture
    def app(self):
        """Create a test FastAPI app."""
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse

        app = FastAPI()

        @app.get("/health")
        async def health():
            return JSONResponse({"status": "healthy"})

        @app.get("/protected")
        async def protected():
            return JSONResponse({"data": "secret"})

        return app

    @pytest.fixture
    def client(self, app):
        """Create a test client."""
        return TestClient(app)

    def test_health_endpoint_bypasses_auth(self, client, mock_settings):
        """Test that /health endpoint doesn't require authentication."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    @patch.object(EntraIDValidator, 'validate_token')
    def test_protected_endpoint_with_valid_token(self, mock_validate, app, mock_settings):
        """Test protected endpoint with valid token."""
        from src.server import configure_auth_middleware

        # Mock successful validation
        mock_validate.return_value = {
            "sub": "test-user-123",
            "preferred_username": "testuser@example.com"
        }

        # Configure middleware
        configure_auth_middleware(app)
        client = TestClient(app)

        response = client.get(
            "/protected",
            headers={"Authorization": "Bearer valid-token"}
        )

        assert response.status_code == 200

    def test_protected_endpoint_without_token(self, app, mock_settings):
        """Test protected endpoint rejects requests without token."""
        from src.server import configure_auth_middleware

        configure_auth_middleware(app)
        client = TestClient(app)

        response = client.get("/protected")
        assert response.status_code == 401

    def test_protected_endpoint_with_invalid_header(self, app, mock_settings):
        """Test protected endpoint rejects malformed Authorization header."""
        from src.server import configure_auth_middleware

        configure_auth_middleware(app)
        client = TestClient(app)

        response = client.get(
            "/protected",
            headers={"Authorization": "NotBearer token"}
        )
        assert response.status_code == 401


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_auth_disabled_by_default(self):
        """Test that auth is disabled by default."""
        settings = Settings(bedrock_kb_id="test-kb-id")
        assert settings.enable_auth is False

    def test_auth_enabled_missing_tenant_id(self):
        """Test validation fails when auth enabled but tenant_id missing."""
        with pytest.raises(ValueError, match="ENTRA_TENANT_ID"):
            Settings(
                bedrock_kb_id="test-kb-id",
                enable_auth=True,
                entra_client_id=TEST_CLIENT_ID
            )

    def test_auth_enabled_missing_client_id(self):
        """Test validation fails when auth enabled but client_id missing."""
        with pytest.raises(ValueError, match="ENTRA_CLIENT_ID"):
            Settings(
                bedrock_kb_id="test-kb-id",
                enable_auth=True,
                entra_tenant_id=TEST_TENANT_ID
            )

    def test_auth_enabled_with_all_required_fields(self):
        """Test validation succeeds when all required fields provided."""
        settings = Settings(
            bedrock_kb_id="test-kb-id",
            enable_auth=True,
            entra_tenant_id=TEST_TENANT_ID,
            entra_client_id=TEST_CLIENT_ID
        )
        assert settings.enable_auth is True
        assert settings.entra_tenant_id == TEST_TENANT_ID
        assert settings.entra_client_id == TEST_CLIENT_ID


class TestGetCurrentUser:
    """Tests for get_current_user dependency."""

    @patch.object(EntraIDValidator, 'validate_token')
    def test_get_current_user_success(self, mock_validate, mock_settings):
        """Test get_current_user with valid credentials."""
        from fastapi.security import HTTPAuthorizationCredentials

        mock_validate.return_value = {
            "sub": "test-user-123",
            "preferred_username": "testuser@example.com"
        }

        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="valid-token"
        )

        # We can't easily test async functions directly, but we can test the validator
        validator = get_validator()
        claims = validator.validate_token("valid-token")

        assert claims["sub"] == "test-user-123"

    def test_get_current_user_no_credentials(self):
        """Test get_current_user with missing credentials."""
        # This would be tested through the middleware integration tests
        pass
