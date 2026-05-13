"""Strict scope enforcement — prevents ANY out-of-scope activity."""

from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger(__name__)


class ScopeGuard:
    """Validates targets against authorized scope definitions.

    Ensures all recon activity stays strictly within the defined scope.
    Any out-of-scope target is BLOCKED and logged.
    """

    def __init__(self) -> None:
        self._in_scope_domains: set[str] = set()
        self._in_scope_wildcards: set[str] = set()
        self._in_scope_ips: set[str] = set()
        self._in_scope_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._out_of_scope_domains: set[str] = set()
        self._out_of_scope_wildcards: set[str] = set()

    def add_scope(self, value: str, is_in_scope: bool = True) -> None:
        """Add a scope entry."""
        value = value.strip().lower()
        value = re.sub(r"^https?://", "", value).split("/")[0]

        if value.startswith("*."):
            target = self._in_scope_wildcards if is_in_scope else self._out_of_scope_wildcards
            target.add(value[2:])  # Store without *.
        elif "/" in value:
            try:
                network = ipaddress.ip_network(value, strict=False)
                if is_in_scope:
                    self._in_scope_cidrs.append(network)
            except ValueError:
                pass
        elif self._is_ip(value):
            if is_in_scope:
                self._in_scope_ips.add(value)
        else:
            target = self._in_scope_domains if is_in_scope else self._out_of_scope_domains
            target.add(value)

    def is_in_scope(self, target: str) -> bool:
        """Check if a target is within the authorized scope.

        Args:
            target: Domain, IP, URL, or hostname to validate.

        Returns:
            True if in scope, False if out of scope.
        """
        target = target.strip().lower()
        target = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]

        # Check out-of-scope first (exclusions take priority)
        if target in self._out_of_scope_domains:
            logger.warning("OUT OF SCOPE (explicit exclusion)", target=target)
            return False

        for wildcard in self._out_of_scope_wildcards:
            if target == wildcard or target.endswith(f".{wildcard}"):
                logger.warning("OUT OF SCOPE (wildcard exclusion)", target=target)
                return False

        # Check in-scope: exact domain match
        if target in self._in_scope_domains:
            return True

        # Check in-scope: wildcard match
        for wildcard in self._in_scope_wildcards:
            if target == wildcard or target.endswith(f".{wildcard}"):
                return True

        # Check in-scope: IP match
        if self._is_ip(target):
            if target in self._in_scope_ips:
                return True
            try:
                ip = ipaddress.ip_address(target)
                for cidr in self._in_scope_cidrs:
                    if ip in cidr:
                        return True
            except ValueError:
                pass

        logger.warning("OUT OF SCOPE", target=target)
        return False

    def validate_url(self, url: str) -> bool:
        """Validate a full URL is in scope."""
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        return self.is_in_scope(hostname)

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @property
    def scope_summary(self) -> dict:
        return {
            "in_scope_domains": list(self._in_scope_domains),
            "in_scope_wildcards": [f"*.{w}" for w in self._in_scope_wildcards],
            "in_scope_ips": list(self._in_scope_ips),
            "in_scope_cidrs": [str(c) for c in self._in_scope_cidrs],
            "out_of_scope_domains": list(self._out_of_scope_domains),
            "out_of_scope_wildcards": [f"*.{w}" for w in self._out_of_scope_wildcards],
        }


def validate_target_in_scope(guard: ScopeGuard, target: str) -> bool:
    """Validate a target is in scope. Raises ValueError if not."""
    if not guard.is_in_scope(target):
        raise ValueError(f"Target '{target}' is OUT OF SCOPE. Operation blocked.")
    return True
