"""JWT Weakness Testing Module."""
from __future__ import annotations
import json, base64
from typing import Any
import httpx, jwt, structlog
from src.core.module_runner import VulnModule
logger = structlog.get_logger(__name__)

class JWTWeaknessModule(VulnModule):
    name = "jwt_weakness_scanner"
    category = "jwt_weakness"
    description = "JWT algorithm confusion, weak secrets, and manipulation"

    WEAK_SECRETS = ["secret", "password", "123456", "key", "jwt_secret", "", "changeme",
                    "your-256-bit-secret", "shhh", "supersecret"]

    async def test(self, target: str, params: dict, auth: Any = None,
                   hypothesis: dict | None = None) -> list[dict[str, Any]]:
        findings = []
        # Try to extract JWT from auth config or response
        token = None
        if auth and hasattr(auth, 'credentials'):
            token = auth.credentials.get("token") or auth.credentials.get("jwt")

        if not token:
            return findings

        try:
            # Decode header without verification
            header = jwt.get_unverified_header(token)
            payload_data = jwt.decode(token, options={"verify_signature": False})

            # Check for 'none' algorithm
            try:
                none_token = jwt.encode(payload_data, "", algorithm="none")
                findings.append({
                    "title": "JWT 'none' algorithm may be accepted",
                    "severity": "critical", "category": "jwt_weakness",
                    "affected_url": target, "confidence": 0.6,
                    "evidence": {"original_alg": header.get("alg"), "test": "none_algorithm"},
                    "source_tool": self.name,
                    "description": "JWT may accept 'none' algorithm, bypassing signature verification",
                })
            except Exception:
                pass

            # Test weak secrets
            for secret in self.WEAK_SECRETS:
                try:
                    jwt.decode(token, secret, algorithms=["HS256", "HS384", "HS512"])
                    findings.append({
                        "title": f"JWT signed with weak secret: '{secret}'",
                        "severity": "critical", "category": "jwt_weakness",
                        "affected_url": target, "confidence": 0.95,
                        "evidence": {"weak_secret": secret, "algorithm": header.get("alg")},
                        "source_tool": self.name,
                        "description": f"JWT secret is guessable: '{secret}'",
                    })
                    break
                except jwt.InvalidSignatureError:
                    pass
                except Exception:
                    pass

            # Check expiration
            if "exp" not in payload_data:
                findings.append({
                    "title": "JWT has no expiration claim",
                    "severity": "medium", "category": "jwt_weakness",
                    "affected_url": target, "confidence": 0.9,
                    "evidence": {"claims": list(payload_data.keys())},
                    "source_tool": self.name,
                    "description": "JWT token never expires, increasing risk if compromised",
                })

        except Exception as e:
            logger.debug("JWT analysis failed", error=str(e))

        return findings
