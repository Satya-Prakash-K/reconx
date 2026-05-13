"""Vulnerability Module Runner — loads and executes vuln testing modules."""

from __future__ import annotations

import asyncio
from typing import Any, Optional

import structlog

logger = structlog.get_logger(__name__)


class VulnModule:
    """Base class for vulnerability testing modules."""

    name: str = "base"
    category: str = "unknown"
    description: str = ""

    async def test(self, target: str, params: dict, auth: Any = None,
                   hypothesis: dict | None = None) -> list[dict[str, Any]]:
        """Run the vulnerability test. Override in subclasses."""
        raise NotImplementedError


class VulnModuleRunner:
    """Discovers and runs vulnerability testing modules against targets."""

    def __init__(self):
        self._modules: dict[str, VulnModule] = {}
        self._load_modules()

    def _load_modules(self):
        """Load all vulnerability testing modules."""
        from src.modules.xss_module import XSSModule
        from src.modules.sqli_module import SQLiModule
        from src.modules.ssrf_module import SSRFModule
        from src.modules.idor_module import IDORModule
        from src.modules.auth_module import AuthFlawModule
        from src.modules.authz_module import AuthzBypassModule
        from src.modules.jwt_module import JWTWeaknessModule
        from src.modules.graphql_module import GraphQLModule
        from src.modules.file_upload_module import FileUploadModule
        from src.modules.redirect_module import OpenRedirectModule
        from src.modules.cors_module import CORSModule
        from src.modules.api_security_module import APISecurityModule
        from src.modules.data_exposure_module import DataExposureModule
        from src.modules.misconfig_module import MisconfigModule
        from src.modules.cloud_module import CloudExposureModule

        modules = [
            XSSModule(), SQLiModule(), SSRFModule(), IDORModule(),
            AuthFlawModule(), AuthzBypassModule(), JWTWeaknessModule(),
            GraphQLModule(), FileUploadModule(), OpenRedirectModule(),
            CORSModule(), APISecurityModule(), DataExposureModule(),
            MisconfigModule(), CloudExposureModule(),
        ]
        for mod in modules:
            self._modules[mod.category] = mod
            logger.info("Loaded vuln module", name=mod.name, category=mod.category)

    async def run_modules(
        self,
        targets: list[str],
        categories: list,
        auth: Any = None,
        hypotheses: list[dict] | None = None,
    ) -> list[dict[str, Any]]:
        """Run applicable modules against targets."""
        findings: list[dict[str, Any]] = []
        category_values = [c.value if hasattr(c, 'value') else str(c) for c in categories]

        tasks = []
        for target in targets[:100]:  # Safety limit
            for cat in category_values:
                module = self._modules.get(cat)
                if module:
                    # Find relevant hypotheses for this target/category
                    relevant_hyp = None
                    if hypotheses:
                        for h in hypotheses:
                            if h.get("category") == cat and h.get("target") == target:
                                relevant_hyp = h
                                break

                    tasks.append(self._run_single(module, target, auth, relevant_hyp))

        # Run with concurrency limit
        sem = asyncio.Semaphore(10)

        async def bounded(coro):
            async with sem:
                return await coro

        results = await asyncio.gather(*[bounded(t) for t in tasks], return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.warning("Module execution error", error=str(result))

        logger.info("Module runner complete", modules_run=len(tasks), findings=len(findings))
        return findings

    async def _run_single(self, module: VulnModule, target: str,
                          auth: Any, hypothesis: dict | None) -> list[dict]:
        try:
            return await asyncio.wait_for(
                module.test(target, {}, auth, hypothesis),
                timeout=120.0,
            )
        except asyncio.TimeoutError:
            logger.warning("Module timed out", module=module.name, target=target)
            return []
        except Exception as e:
            logger.warning("Module failed", module=module.name, error=str(e))
            return []
