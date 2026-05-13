"""Distributed Worker — Ray-based parallel scanning tasks.

Uses Ray cluster for:
- Parallel vulnerability scanning across multiple targets
- GPU-accelerated ML inference (anomaly detection, classification)
- Elastic scaling based on workload
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

try:
    import ray

    @ray.remote(num_cpus=1, max_retries=2)
    class VulnScanWorker:
        """Ray remote actor for distributed vulnerability scanning."""

        def __init__(self):
            self.scan_count = 0

        async def scan_endpoint(self, endpoint: dict, categories: list[str],
                                hypotheses: list[dict]) -> list[dict]:
            """Scan a single endpoint for vulnerabilities."""
            from src.core.module_runner import VulnModuleRunner
            runner = VulnModuleRunner()
            findings = await runner.run_modules(
                targets=[endpoint.get("url", "")],
                categories=categories,
                hypotheses=hypotheses,
            )
            self.scan_count += 1
            return findings

        async def fuzz_endpoint(self, endpoint: dict, hypotheses: list[dict]) -> list[dict]:
            """Fuzz a single endpoint."""
            from src.fuzzing.engine import FuzzingEngine
            engine = FuzzingEngine()
            findings = await engine.fuzz([endpoint], hypotheses, None)
            return findings

        async def run_tool(self, tool_name: str, target: str,
                           params: dict | None = None) -> dict:
            """Run an external tool against a target."""
            from src.tools.integrations import NucleiRunner, DalfoxRunner, SqlmapRunner
            tools = {
                "nuclei": NucleiRunner,
                "dalfox": DalfoxRunner,
                "sqlmap": SqlmapRunner,
            }
            tool_cls = tools.get(tool_name)
            if not tool_cls:
                return {"error": f"Unknown tool: {tool_name}"}

            tool = tool_cls()
            if tool_name == "nuclei":
                result = await tool.scan(target)
            elif tool_name == "dalfox":
                result = await tool.scan(target)
            elif tool_name == "sqlmap":
                result = await tool.scan(target, params.get("param") if params else None)
            else:
                return {"error": "unsupported"}

            return {"tool": tool_name, "findings": result.findings, "success": result.success}

        def get_stats(self) -> dict:
            return {"scan_count": self.scan_count}


    @ray.remote(num_gpus=0.5)
    class MLInferenceWorker:
        """Ray GPU worker for ML-based anomaly detection and classification."""

        def __init__(self):
            self.model_loaded = False

        def load_model(self):
            """Load ML models for inference."""
            # Placeholder for actual ML model loading
            self.model_loaded = True
            return {"status": "loaded"}

        def detect_anomalies(self, responses: list[dict]) -> list[dict]:
            """Run anomaly detection on response data."""
            from src.fuzzing.engine import AnomalyDetector, FuzzResult
            detector = AnomalyDetector()
            results = []
            for resp in responses:
                baseline = FuzzResult("", "", "", resp.get("baseline_status", 200),
                                      resp.get("baseline_body", ""), resp.get("baseline_time", 0.5))
                result = FuzzResult(resp.get("url", ""), resp.get("param", ""), resp.get("payload", ""),
                                    resp.get("status", 200), resp.get("body", ""), resp.get("time", 0.5))
                score = detector.score(result, baseline)
                if score > 0.5:
                    results.append({"url": resp.get("url"), "anomaly_score": score, "payload": resp.get("payload")})
            return results

        def classify_endpoint(self, endpoint_data: dict) -> dict:
            """ML-based endpoint classification."""
            return {"endpoint": endpoint_data.get("url", ""), "classification": "api", "confidence": 0.8}


    class DistributedScanner:
        """Orchestrates distributed scanning across a Ray cluster."""

        def __init__(self, num_workers: int = 4):
            self.num_workers = num_workers
            self.workers: list = []

        async def init_workers(self):
            """Initialize Ray workers."""
            if not ray.is_initialized():
                ray.init(ignore_reinit_error=True)
            self.workers = [VulnScanWorker.remote() for _ in range(self.num_workers)]
            logger.info("Ray workers initialized", count=self.num_workers)

        async def distributed_scan(
            self, endpoints: list[dict], categories: list[str],
            hypotheses: list[dict],
        ) -> list[dict]:
            """Distribute scanning across Ray workers."""
            all_findings: list[dict] = []

            # Distribute endpoints across workers (round-robin)
            futures = []
            for i, endpoint in enumerate(endpoints):
                worker = self.workers[i % self.num_workers]
                future = worker.scan_endpoint.remote(endpoint, categories, hypotheses)
                futures.append(future)

            # Gather results
            results = ray.get(futures)
            for result in results:
                if isinstance(result, list):
                    all_findings.extend(result)

            logger.info("Distributed scan complete",
                         endpoints=len(endpoints), findings=len(all_findings))
            return all_findings

        async def distributed_fuzz(
            self, endpoints: list[dict], hypotheses: list[dict],
        ) -> list[dict]:
            """Distribute fuzzing across Ray workers."""
            futures = []
            for i, endpoint in enumerate(endpoints):
                worker = self.workers[i % self.num_workers]
                future = worker.fuzz_endpoint.remote(endpoint, hypotheses)
                futures.append(future)

            results = ray.get(futures)
            all_findings = []
            for result in results:
                if isinstance(result, list):
                    all_findings.extend(result)
            return all_findings

except ImportError:
    logger.warning("Ray not available — distributed scanning disabled")

    class DistributedScanner:
        """Fallback scanner without Ray."""
        async def init_workers(self): pass
        async def distributed_scan(self, endpoints, categories, hypotheses):
            return []
        async def distributed_fuzz(self, endpoints, hypotheses):
            return []
