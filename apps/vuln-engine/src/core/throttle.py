"""Smart Throttle & Anti-WAF Adaptive Engine.

Features:
- Dynamic request rate adjustment based on response codes
- WAF detection and evasion strategies
- Session handling with cookie jar management
- Automatic backoff on rate limiting
- Fingerprint randomization
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)


class SmartThrottle:
    """Adaptive request throttling with WAF awareness."""

    def __init__(self, initial_rps: float = 10.0, min_rps: float = 0.5, max_rps: float = 50.0):
        self.current_rps = initial_rps
        self.min_rps = min_rps
        self.max_rps = max_rps
        self._consecutive_blocks = 0
        self._last_request = 0.0
        self._request_count = 0

    async def wait(self):
        """Wait appropriate time between requests."""
        delay = 1.0 / self.current_rps
        elapsed = time.monotonic() - self._last_request
        if elapsed < delay:
            await asyncio.sleep(delay - elapsed)
        self._last_request = time.monotonic()
        self._request_count += 1

    def on_response(self, status_code: int):
        """Adjust throttle based on response."""
        if status_code == 429:
            # Rate limited — back off significantly
            self.current_rps = max(self.min_rps, self.current_rps * 0.3)
            self._consecutive_blocks += 1
            logger.info("Rate limited — slowing down", rps=self.current_rps)
        elif status_code == 403:
            # Potential WAF block
            self._consecutive_blocks += 1
            if self._consecutive_blocks > 3:
                self.current_rps = max(self.min_rps, self.current_rps * 0.5)
                logger.warning("WAF blocks detected — throttling", rps=self.current_rps)
        else:
            # Success — gradually speed up
            self._consecutive_blocks = 0
            if self._request_count % 50 == 0:
                self.current_rps = min(self.max_rps, self.current_rps * 1.1)

    @property
    def is_blocked(self) -> bool:
        return self._consecutive_blocks > 10


class WAFEvasion:
    """Anti-WAF adaptive behavior for payload delivery."""

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Mobile Safari/604.1",
    ]

    ENCODING_STRATEGIES = [
        ("url_encode", lambda p: p.replace("<", "%3C").replace(">", "%3E").replace("'", "%27")),
        ("double_url", lambda p: p.replace("<", "%253C").replace(">", "%253E")),
        ("unicode", lambda p: p.replace("<", "\u003c").replace(">", "\u003e")),
        ("html_entity", lambda p: p.replace("<", "&#60;").replace(">", "&#62;")),
        ("case_swap", lambda p: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p))),
        ("null_byte", lambda p: p.replace("script", "scr%00ipt")),
        ("comment_insert", lambda p: p.replace("SELECT", "SEL/**/ECT").replace("UNION", "UNI/**/ON")),
        ("concat", lambda p: p.replace("alert", "al"+"ert")),
    ]

    def __init__(self):
        self._waf_fingerprint: str | None = None
        self._successful_strategy: str | None = None

    def detect_waf(self, response: httpx.Response) -> dict[str, Any]:
        """Detect WAF presence and type."""
        waf_signatures = {
            "cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
            "akamai": ["akamai", "x-akamai"],
            "aws_waf": ["x-amzn-requestid", "awselb"],
            "incapsula": ["incap_ses", "x-cdn", "imperva"],
            "sucuri": ["x-sucuri-id", "sucuri"],
            "modsecurity": ["mod_security", "NOYB"],
            "f5_bigip": ["x-cnection", "bigipserver"],
        }

        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        body_lower = response.text.lower() if response.text else ""

        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig in " ".join(headers_lower.keys()) + " ".join(headers_lower.values()) + body_lower:
                    self._waf_fingerprint = waf_name
                    return {"detected": True, "waf": waf_name, "confidence": 0.8}

        if response.status_code == 403:
            return {"detected": True, "waf": "unknown", "confidence": 0.5}

        return {"detected": False, "waf": None, "confidence": 0.0}

    def get_evasion_headers(self) -> dict[str, str]:
        """Generate randomized headers for WAF evasion."""
        return {
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": random.choice(["en-US,en;q=0.5", "en-GB,en;q=0.5", "fr-FR,fr;q=0.9"]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Cache-Control": random.choice(["no-cache", "max-age=0"]),
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }

    def evade_payload(self, payload: str) -> list[str]:
        """Generate WAF-evading variants of a payload."""
        variants = [payload]
        for name, transformer in self.ENCODING_STRATEGIES:
            try:
                variant = transformer(payload)
                if variant != payload:
                    variants.append(variant)
            except Exception:
                pass
        return variants


class SessionManager:
    """Manages authenticated sessions and cookies across scans."""

    def __init__(self):
        self._sessions: dict[str, httpx.AsyncClient] = {}

    async def get_session(self, session_id: str, auth_config: dict | None = None) -> httpx.AsyncClient:
        """Get or create an authenticated session."""
        if session_id in self._sessions:
            return self._sessions[session_id]

        client = httpx.AsyncClient(timeout=20.0, verify=False, follow_redirects=True)

        if auth_config:
            auth_type = auth_config.get("auth_type", "bearer")
            if auth_type == "bearer":
                token = auth_config.get("credentials", {}).get("token", "")
                client.headers["Authorization"] = f"Bearer {token}"
            elif auth_type == "cookie":
                cookies = auth_config.get("session_cookies", {})
                for name, value in cookies.items():
                    client.cookies.set(name, value)
            elif auth_type == "basic":
                import base64
                creds = auth_config.get("credentials", {})
                encoded = base64.b64encode(f"{creds.get('username', '')}:{creds.get('password', '')}".encode()).decode()
                client.headers["Authorization"] = f"Basic {encoded}"
            elif auth_type == "login":
                # Perform login flow
                login_url = auth_config.get("login_url", "")
                login_payload = auth_config.get("login_payload", {})
                if login_url:
                    resp = await client.post(login_url, json=login_payload)
                    if resp.status_code == 200:
                        token_field = auth_config.get("token_field", "access_token")
                        try:
                            token = resp.json().get(token_field, "")
                            client.headers["Authorization"] = f"Bearer {token}"
                        except Exception:
                            pass

        self._sessions[session_id] = client
        return client

    async def close_all(self):
        for client in self._sessions.values():
            await client.aclose()
        self._sessions.clear()
