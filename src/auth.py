"""Microsoft Entra ID (Azure AD) JWT token validation."""

import time
from functools import lru_cache
from typing import Dict, Any

import requests
import structlog
from fastapi import HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError, jwk
from jose.backends import RSAKey

from .config import settings

logger = structlog.get_logger()

# HTTP Bearer scheme for FastAPI
security = HTTPBearer()


class EntraIDValidator:
    """
    Validates JWT tokens issued by Microsoft Entra ID (Azure AD).

    This class:
    - Fetches JWKS (JSON Web Key Sets) from Azure AD
    - Caches signing keys for performance
    - Validates JWT signatures using RS256 algorithm
    - Verifies standard claims (iss, aud, exp, nbf)
    - Returns decoded user claims for logging/authorization
    """

    def __init__(self):
        """Initialize the Entra ID validator with configuration from settings."""
        if not settings.entra_tenant_id or not settings.entra_client_id:
            raise ValueError(
                "ENTRA_TENANT_ID and ENTRA_CLIENT_ID must be set when auth is enabled"
            )

        self.tenant_id = settings.entra_tenant_id
        self.client_id = settings.entra_client_id

        # Audience can be customized, defaults to client_id
        # Common patterns: client_id, api://client_id, or custom audience
        self.audience = getattr(settings, 'entra_audience', None) or self.client_id

        # Expected issuer for tokens from this tenant
        self.issuer = f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

        # JWKS endpoint to fetch public keys
        self.jwks_uri = f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"

        # Cache for signing keys
        self._signing_keys_cache: Dict[str, Any] = {}
        self._cache_timestamp = 0
        self._cache_ttl = 3600  # 1 hour TTL

        logger.info(
            "entra_validator_initialized",
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            audience=self.audience,
            issuer=self.issuer
        )

    def get_signing_keys(self) -> Dict[str, Any]:
        """
        Fetch JWKS (JSON Web Key Set) from Azure AD.

        This method caches the signing keys for 1 hour to avoid excessive
        requests to Azure AD. The cache is invalidated after TTL expires.

        Returns:
            Dictionary mapping key IDs (kid) to public keys

        Raises:
            HTTPException: If fetching JWKS fails
        """
        current_time = time.time()

        # Return cached keys if still valid
        if (self._signing_keys_cache and
            current_time - self._cache_timestamp < self._cache_ttl):
            return self._signing_keys_cache

        # Fetch fresh keys from Azure AD
        try:
            logger.debug("fetching_jwks", uri=self.jwks_uri)
            response = requests.get(self.jwks_uri, timeout=10)
            response.raise_for_status()
            jwks = response.json()

            # Build key dictionary indexed by kid
            signing_keys = {}
            for key_data in jwks.get("keys", []):
                kid = key_data.get("kid")
                if kid:
                    signing_keys[kid] = key_data

            # Update cache
            self._signing_keys_cache = signing_keys
            self._cache_timestamp = current_time

            logger.info(
                "jwks_fetched",
                key_count=len(signing_keys),
                cache_ttl=self._cache_ttl
            )

            return signing_keys

        except requests.RequestException as e:
            logger.error("jwks_fetch_failed", error=str(e), uri=self.jwks_uri)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Failed to fetch signing keys from Azure AD: {str(e)}"
            )

    def get_public_key(self, token: str) -> RSAKey:
        """
        Extract the public key for verifying a JWT token.

        Args:
            token: The JWT token string

        Returns:
            RSA public key for signature verification

        Raises:
            HTTPException: If key ID (kid) is missing or key not found
        """
        try:
            # Decode header without verification to get kid
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")

            if not kid:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token missing 'kid' (key ID) in header"
                )

            # Get signing keys
            signing_keys = self.get_signing_keys()

            # Find the key matching the kid
            key_data = signing_keys.get(kid)
            if not key_data:
                logger.warning(
                    "unknown_key_id",
                    kid=kid,
                    available_kids=list(signing_keys.keys())
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Token signed with unknown key ID: {kid}"
                )

            # Construct RSA public key from JWK
            public_key = jwk.construct(key_data)
            return public_key

        except JWTError as e:
            logger.error("jwt_header_decode_error", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token format: {str(e)}"
            )

    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate a JWT token from Azure AD.

        This method:
        1. Extracts the public key using the token's kid
        2. Verifies the signature using RS256
        3. Validates standard claims (iss, aud, exp, nbf)
        4. Returns decoded claims

        Args:
            token: The JWT access token string

        Returns:
            Dictionary of decoded token claims (sub, email, name, etc.)

        Raises:
            HTTPException: If validation fails for any reason
        """
        try:
            # Get the public key for this token
            public_key = self.get_public_key(token)

            # Decode and validate token
            decoded_token = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                }
            )

            logger.debug(
                "token_validated",
                subject=decoded_token.get("sub"),
                user=decoded_token.get("preferred_username", "unknown")
            )

            return decoded_token

        except jwt.ExpiredSignatureError:
            logger.warning("token_expired")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.JWTClaimsError as e:
            # Covers audience, issuer, nbf validation failures
            logger.warning("token_claims_invalid", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token claims: {str(e)}"
            )
        except JWTError as e:
            logger.warning("token_validation_failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token validation failed: {str(e)}"
            )
        except HTTPException:
            # Re-raise HTTPExceptions from get_public_key
            raise
        except Exception as e:
            logger.error("unexpected_validation_error", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal authentication error"
            )


# Global validator instance (initialized when auth is enabled)
_validator: EntraIDValidator | None = None


def get_validator() -> EntraIDValidator:
    """
    Get or create the global EntraIDValidator instance.

    Returns:
        The configured EntraIDValidator

    Raises:
        ValueError: If auth is enabled but validator cannot be initialized
    """
    global _validator
    if _validator is None:
        _validator = EntraIDValidator()
    return _validator


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> Dict[str, Any]:
    """
    FastAPI dependency to validate JWT token and extract user claims.

    This dependency can be used in route handlers to protect endpoints:

    ```python
    @app.get("/protected")
    async def protected_route(user: dict = Depends(get_current_user)):
        return {"user": user["preferred_username"]}
    ```

    Args:
        credentials: HTTP Bearer token from Authorization header

    Returns:
        Dictionary of user claims from validated token

    Raises:
        HTTPException: If token is missing or invalid
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header"
        )

    token = credentials.credentials

    # Get validator and validate token
    validator = get_validator()
    user_claims = validator.validate_token(token)

    return user_claims
