"""Trusted Networks with Forward auth provider.

It tests for a Cookie and X-Forwarded-User header and performs an HMAC
validation of the cookie header.
Abort login flow if not access from trusted network or cookie is invalid.
"""
import base64
import hashlib
import hmac
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_network
import logging
import time
from typing import Any, Dict, List, Optional, Union, cast

import voluptuous as vol

from homeassistant.core import callback
from homeassistant.exceptions import HomeAssistantError
import homeassistant.helpers.config_validation as cv

from . import AUTH_PROVIDER_SCHEMA, AUTH_PROVIDERS, AuthProvider, LoginFlow
from ..models import Credentials, UserMeta

_LOGGER = logging.getLogger(__name__)

IPAddress = Union[IPv4Address, IPv6Address]
IPNetwork = Union[IPv4Network, IPv6Network]

CONF_TRUSTED_NETWORKS = "trusted_networks"
CONF_COOKIE_SECRET = "cookie_secret"
CONF_COOKIE_NAME = "cookie_name"
CONF_COOKIE_DOMAIN = "cookie_domain"
CONF_HEADER_COOKIE = "header_cookie"
CONF_HEADER_USER = "header_user"

CONFIG_SCHEMA = AUTH_PROVIDER_SCHEMA.extend(
    {
        vol.Required(CONF_TRUSTED_NETWORKS): vol.All(cv.ensure_list, [ip_network]),
        vol.Required(CONF_COOKIE_SECRET): str,
        vol.Required(CONF_COOKIE_DOMAIN): str,
        vol.Required(CONF_COOKIE_NAME): str,
        vol.Optional(CONF_HEADER_COOKIE, default="Cookie"): str,
        vol.Optional(CONF_HEADER_USER, default="X-Forwarded-User"): str,
    },
    extra=vol.PREVENT_EXTRA,
)


class InvalidAuthError(HomeAssistantError):
    """Raised when try to access from untrusted networks."""


class InvalidUserError(HomeAssistantError):
    """Raised when try to login as invalid user."""


@AUTH_PROVIDERS.register("trusted_forward_auth")
class TrustedForwardAuthProvider(AuthProvider):
    """Trusted Networks auth provider.

    Allow passwordless access from trusted network.
    """

    DEFAULT_TITLE = "Trusted Networks with Forward Authentication"

    @property
    def trusted_networks(self) -> List[IPNetwork]:
        """Return trusted networks."""
        return cast(List[IPNetwork], self.config[CONF_TRUSTED_NETWORKS])

    @property
    def support_mfa(self) -> bool:
        """Trusted Networks auth provider does not support MFA."""
        return False

    async def async_login_flow(self, context: Optional[Dict]) -> LoginFlow:
        """Return a flow to login."""
        assert context is not None
        ip_addr = cast(IPAddress, context.get("ip_address"))
        headers = context.get("headers", {})
        username = headers.get(self.config[CONF_HEADER_USER])
        auth_cookie = headers.get(self.config[CONF_HEADER_COOKIE])

        return TrustedForwardAuthLoginFlow(self, ip_addr, auth_cookie, username)

    async def async_get_or_create_credentials(
        self, flow_result: Dict[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""
        username = flow_result["user"]

        users = await self.store.async_get_users()
        for user in users:
            if not user.system_generated and user.is_active and user.name == username:
                for credential in await self.async_credentials():
                    if credential.data["username"] == username:
                        return credential
                cred = self.async_create_credentials({"username": username})
                await self.store.async_link_user(user, cred)
                return cred

        # We only allow login as exist user
        raise InvalidUserError

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return extra user metadata for credentials.

        Trusted network auth provider should never create new user.
        """
        raise NotImplementedError

    def validate_hmac_cookie(self, cookie):
        """Validate the HMAC provided in a cookie from the Forward Auth provider.

        This expects a cookie header to be present in the form:
        cookieName=token|expiration|username

        """
        cookie_content = cookie.split("=", 1)
        if len(cookie_content) != 2:
            _LOGGER.warning(
                "Failed to validate Forward Auth cookie. Invalid Cookie Format."
            )
            return False

        if cookie_content[0] != self.config[CONF_COOKIE_NAME]:
            _LOGGER.warning(
                "Failed to validate Forward Auth cookie. Wrong Cookie Name."
            )
            return False

        parts = cookie_content[1].split("|")
        if len(parts) != 3:
            _LOGGER.warning(
                "Failed to validate Forward Auth cookie. Invalid Cookie Format."
            )
            return False

        try:
            decoded_signature = base64.urlsafe_b64decode(parts[0])
        except Exception:
            _LOGGER.warning(
                "Failed to validate Forward Auth cookie. Unable to decode cookie HMAC."
            )
            return False

        try:
            expected_signature = self.generate_hmac_cookie(parts[2], parts[1])
        except Exception:
            _LOGGER.warning(
                "Failed to validate Forward Auth cookie. Unable to generate expected HMAC."
            )
            return False

        if not hmac.compare_digest(decoded_signature, expected_signature):
            _LOGGER.warning(
                "Failed to validate Forward Auth cookie. Invalid cookie HMAC."
            )
            return False

        try:
            if int(time.time()) > int(parts[1]):
                _LOGGER.warning(
                    "Failed to validate Forward Auth cookie. Cookie is expired."
                )
                return False
        except TypeError:
            _LOGGER.warning(
                "Failed to validate Forward Auth cookie. Unable to Parse Cookie Expiry."
            )
            return False

        _LOGGER.debug("Successfully validated user %s", parts[2])
        return True

    def generate_hmac_cookie(self, email, expires):
        """Generate an equivalent signature for verification."""
        message = "{}{}{}".format(
            self.config[CONF_COOKIE_DOMAIN], email, expires
        ).encode("utf-8")
        signature = hmac.new(
            self.config[CONF_COOKIE_SECRET].encode("utf-8"),
            message,
            digestmod=hashlib.sha256,
        ).digest()
        return signature

    @callback
    def async_validate_access(
        self, ip_addr: IPAddress, auth_cookie: Optional[str]
    ) -> None:
        """Make sure the access from trusted networks.

        Raise InvalidAuthError if not.
        Raise InvalidAuthError if forward_auth is not configured.
        """
        if not self.trusted_networks:
            raise InvalidAuthError("trusted_networks is not configured")

        if not any(
            ip_addr in trusted_network for trusted_network in self.trusted_networks
        ):
            raise InvalidAuthError("Not in trusted_networks")

        valid_cookie = self.validate_hmac_cookie(auth_cookie)
        if not valid_cookie:
            raise InvalidAuthError("Invalid forward auth cookie")


class TrustedForwardAuthLoginFlow(LoginFlow):
    """Handler for the login flow."""

    def __init__(
        self,
        auth_provider: TrustedForwardAuthProvider,
        ip_addr: IPAddress,
        auth_cookie: Optional[str],
        username: Optional[str],
    ) -> None:
        """Initialize the login flow."""
        super().__init__(auth_provider)
        self._ip_address = ip_addr
        self._auth_cookie = auth_cookie
        self._username = username

    async def async_step_init(
        self, user_input: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Handle the step of the form."""
        try:
            cast(TrustedForwardAuthProvider, self._auth_provider).async_validate_access(
                self._ip_address, self._auth_cookie
            )

        except InvalidAuthError:
            return self.async_abort(reason="not_whitelisted")

        if not self._username:
            return self.async_abort(reason="no_available_user")

        return await self.async_finish({"user": self._username})
