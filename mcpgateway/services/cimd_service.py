# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/services/cimd_service.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

OAuth Client ID Metadata Document (CIMD) Service.

The gateway acts as a public OAuth client identified by the HTTPS URL of a
metadata document it publishes. This module builds that document and decides
whether an authorization server supports CIMD, so callers can prefer it over
Dynamic Client Registration (RFC 7591, deprecated by MCP 2026-07-28).
"""

# Standard
import logging
from typing import Any, Dict, Optional

# First-Party
from mcpgateway.config import get_settings
from mcpgateway.services.dcr_service import DcrService

logger = logging.getLogger(__name__)

CIMD_DOCUMENT_PATH = "/.well-known/oauth-client"
CIMD_METADATA_FLAG = "client_id_metadata_document_supported"
CIMD_AUTH_METHOD = "none"


class CimdService:
    """Builds the gateway's Client ID Metadata Document and detects authorization server support."""

    def __init__(self, dcr_service: Optional[DcrService] = None) -> None:
        """Initialize the service with the current settings.

        Args:
            dcr_service: Service used for authorization server metadata discovery. Created on first use when omitted.
        """
        self.settings = get_settings()
        self._dcr_service = dcr_service

    @property
    def _base_url(self) -> str:
        """Return the public gateway base URL, derived only from server-side configuration.

        Returns:
            str: ``APP_DOMAIN`` plus ``APP_ROOT_PATH`` without a trailing slash.
        """
        root_path = str(self.settings.app_root_path or "").rstrip("/")
        return f"{str(self.settings.app_domain).rstrip('/')}{root_path}"

    @property
    def client_id(self) -> str:
        """Return the stable URL that identifies the gateway as an OAuth client.

        Returns:
            str: The document URL, which is also the OAuth ``client_id``.

        Examples:
            >>> CimdService().client_id.endswith("/.well-known/oauth-client")
            True
        """
        return f"{self._base_url}{CIMD_DOCUMENT_PATH}"

    @property
    def redirect_uri(self) -> str:
        """Return the callback URL published in the document.

        Returns:
            str: The gateway OAuth callback URL.
        """
        return f"{self._base_url}/oauth/callback"

    def build_document(self) -> Dict[str, Any]:
        """Build the Client ID Metadata Document.

        The document holds no secrets. The gateway is a public client that uses PKCE.

        Returns:
            Dict[str, Any]: The JSON document served at ``client_id``.

        Examples:
            >>> doc = CimdService().build_document()
            >>> doc["client_id"] == CimdService().client_id
            True
            >>> doc["token_endpoint_auth_method"]
            'none'
        """
        return {
            "client_id": self.client_id,
            "client_name": self.settings.cimd_client_name,
            "redirect_uris": [self.redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": CIMD_AUTH_METHOD,
        }

    async def is_applicable(self, issuer: str, redirect_uri: str) -> bool:
        """Return whether CIMD can register the gateway with ``issuer``.

        CIMD applies only when it is enabled, the document is served over HTTPS, the
        callback in use matches the published one, the issuer is permitted, and the
        authorization server advertises ``client_id_metadata_document_supported``.
        Any discovery failure returns ``False`` so the caller falls back to DCR.

        Args:
            issuer: Authorization server issuer URL.
            redirect_uri: Callback URL the authorization request will use.

        Returns:
            bool: ``True`` when CIMD should be used instead of Dynamic Client Registration.

        Examples:
            >>> import asyncio
            >>> from unittest.mock import AsyncMock, Mock
            >>> dcr = Mock(discover_as_metadata=AsyncMock(return_value={"client_id_metadata_document_supported": True}))
            >>> service = CimdService(dcr)
            >>> service.settings = Mock(cimd_enabled=True, app_domain="https://gw.example.com", app_root_path="", well_known_enabled=True, dcr_allowed_issuers=[])
            >>> asyncio.run(service.is_applicable("https://as.example.com", "https://gw.example.com/oauth/callback"))
            True
            >>> asyncio.run(service.is_applicable("https://as.example.com", "https://other.example.com/oauth/callback"))
            False
        """
        if not self.settings.cimd_enabled or not self.settings.well_known_enabled:
            return False
        if not self.client_id.startswith("https://") or redirect_uri != self.redirect_uri:
            return False
        allowed = [i.rstrip("/") for i in self.settings.dcr_allowed_issuers]
        if allowed and issuer.rstrip("/") not in allowed:
            return False

        if self._dcr_service is None:
            self._dcr_service = DcrService()
        try:
            metadata = await self._dcr_service.discover_as_metadata(issuer)
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("CIMD support check failed for %s: %s", issuer, type(exc).__name__)
            return False
        return metadata.get(CIMD_METADATA_FLAG) is True
