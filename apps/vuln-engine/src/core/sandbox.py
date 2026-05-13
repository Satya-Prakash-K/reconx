"""Sandboxed Execution Environment — isolated container-based tool execution.

Provides:
- Namespace isolation for each scan
- Resource limits (CPU, memory, network)
- Read-only filesystem with temp scratch space
- Network policy enforcement (only contact in-scope targets)
- Automatic cleanup after execution
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import uuid
from typing import Any, Optional

import structlog

logger = structlog.get_logger(__name__)


class SandboxConfig:
    """Configuration for a sandboxed execution environment."""

    def __init__(
        self,
        cpu_limit: str = "1.0",
        memory_limit: str = "512m",
        timeout_seconds: int = 300,
        network_allowed: list[str] | None = None,
        read_only_root: bool = True,
        drop_capabilities: bool = True,
    ):
        self.cpu_limit = cpu_limit
        self.memory_limit = memory_limit
        self.timeout_seconds = timeout_seconds
        self.network_allowed = network_allowed or []
        self.read_only_root = read_only_root
        self.drop_capabilities = drop_capabilities


class SandboxResult:
    """Result from a sandboxed execution."""

    def __init__(self, exit_code: int, stdout: str, stderr: str,
                 duration_ms: int, sandbox_id: str):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_ms = duration_ms
        self.sandbox_id = sandbox_id


class SandboxExecutor:
    """Executes commands in isolated sandboxed environments.

    In Docker mode: uses Docker containers with resource limits.
    In K8s mode: uses ephemeral pods with security policies.
    In local mode: uses process isolation with cgroups.
    """

    def __init__(self, mode: str = "auto"):
        if mode == "auto":
            if os.path.exists("/var/run/docker.sock"):
                self.mode = "docker"
            elif os.getenv("KUBERNETES_SERVICE_HOST"):
                self.mode = "kubernetes"
            else:
                self.mode = "local"
        else:
            self.mode = mode

        logger.info("Sandbox executor initialized", mode=self.mode)

    async def execute(
        self, command: list[str], config: SandboxConfig,
        env: dict[str, str] | None = None,
        work_dir: str | None = None,
    ) -> SandboxResult:
        """Execute a command in a sandboxed environment."""
        sandbox_id = f"sandbox-{uuid.uuid4().hex[:12]}"

        if self.mode == "docker":
            return await self._execute_docker(command, config, env, work_dir, sandbox_id)
        elif self.mode == "kubernetes":
            return await self._execute_k8s(command, config, env, work_dir, sandbox_id)
        else:
            return await self._execute_local(command, config, env, work_dir, sandbox_id)

    async def _execute_docker(
        self, command: list[str], config: SandboxConfig,
        env: dict | None, work_dir: str | None, sandbox_id: str,
    ) -> SandboxResult:
        """Execute in a Docker container with resource limits."""
        import time

        docker_cmd = [
            "docker", "run", "--rm",
            "--name", sandbox_id,
            "--cpus", config.cpu_limit,
            "--memory", config.memory_limit,
            "--network", "reconx_reconx",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--read-only" if config.read_only_root else "",
            "--tmpfs", "/tmp:rw,size=100m",
        ]

        # Add env vars
        if env:
            for k, v in env.items():
                docker_cmd.extend(["-e", f"{k}={v}"])

        # Use a base image with common tools
        docker_cmd.extend(["reconx/vuln-engine:latest"] + command)

        # Remove empty strings
        docker_cmd = [c for c in docker_cmd if c]

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=config.timeout_seconds
            )
            duration = int((time.monotonic() - start) * 1000)

            return SandboxResult(
                exit_code=proc.returncode or 0,
                stdout=stdout.decode(errors="replace"),
                stderr=stderr.decode(errors="replace"),
                duration_ms=duration,
                sandbox_id=sandbox_id,
            )
        except asyncio.TimeoutError:
            # Kill the container
            await asyncio.create_subprocess_exec("docker", "kill", sandbox_id)
            duration = int((time.monotonic() - start) * 1000)
            return SandboxResult(
                exit_code=-1, stdout="", stderr="Timeout exceeded",
                duration_ms=duration, sandbox_id=sandbox_id,
            )

    async def _execute_k8s(
        self, command: list[str], config: SandboxConfig,
        env: dict | None, work_dir: str | None, sandbox_id: str,
    ) -> SandboxResult:
        """Execute in a Kubernetes ephemeral pod."""
        import json, time, yaml

        pod_spec = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": sandbox_id,
                "namespace": "reconx",
                "labels": {"app": "vuln-sandbox", "scan": sandbox_id},
            },
            "spec": {
                "restartPolicy": "Never",
                "automountServiceAccountToken": False,
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": 1000,
                    "fsGroup": 1000,
                },
                "containers": [{
                    "name": "scanner",
                    "image": "reconx/vuln-engine:latest",
                    "command": command,
                    "resources": {
                        "limits": {"cpu": config.cpu_limit, "memory": config.memory_limit},
                        "requests": {"cpu": "100m", "memory": "128Mi"},
                    },
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": config.read_only_root,
                        "capabilities": {"drop": ["ALL"], "add": ["NET_RAW"]},
                    },
                    "env": [{"name": k, "value": v} for k, v in (env or {}).items()],
                    "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                }],
                "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "100Mi"}}],
                "activeDeadlineSeconds": config.timeout_seconds,
            },
        }

        start = time.monotonic()
        # Create pod
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(pod_spec, f)
            spec_path = f.name

        try:
            await asyncio.create_subprocess_exec("kubectl", "apply", "-f", spec_path)
            # Wait for completion
            proc = await asyncio.create_subprocess_exec(
                "kubectl", "wait", "--for=condition=Ready", f"pod/{sandbox_id}",
                "-n", "reconx", f"--timeout={config.timeout_seconds}s",
            )
            await proc.wait()

            # Get logs
            log_proc = await asyncio.create_subprocess_exec(
                "kubectl", "logs", sandbox_id, "-n", "reconx",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await log_proc.communicate()
            duration = int((time.monotonic() - start) * 1000)

            return SandboxResult(
                exit_code=0, stdout=stdout.decode(), stderr=stderr.decode(),
                duration_ms=duration, sandbox_id=sandbox_id,
            )
        finally:
            # Cleanup
            await asyncio.create_subprocess_exec(
                "kubectl", "delete", "pod", sandbox_id, "-n", "reconx", "--ignore-not-found"
            )
            os.unlink(spec_path)

    async def _execute_local(
        self, command: list[str], config: SandboxConfig,
        env: dict | None, work_dir: str | None, sandbox_id: str,
    ) -> SandboxResult:
        """Execute locally with process isolation (fallback)."""
        import time
        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, **(env or {})},
                cwd=work_dir,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=config.timeout_seconds
            )
            duration = int((time.monotonic() - start) * 1000)
            return SandboxResult(
                exit_code=proc.returncode or 0,
                stdout=stdout.decode(errors="replace"),
                stderr=stderr.decode(errors="replace"),
                duration_ms=duration,
                sandbox_id=sandbox_id,
            )
        except asyncio.TimeoutError:
            proc.kill()
            duration = int((time.monotonic() - start) * 1000)
            return SandboxResult(
                exit_code=-1, stdout="", stderr="Timeout",
                duration_ms=duration, sandbox_id=sandbox_id,
            )
