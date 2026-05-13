"""Workflow API routes."""

from __future__ import annotations
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class WorkflowRequest(BaseModel):
    template: str = "full_scan"
    workspace_id: str = ""
    targets: list[str] = []
    config: dict = {}


@router.post("/start")
async def start_workflow(request: WorkflowRequest):
    """Start an autonomous workflow."""
    from src.workflows.engine import WorkflowEngine
    engine = WorkflowEngine()
    result = await engine.start(request.template, request.workspace_id, request.targets, request.config)
    return result


@router.get("/templates")
async def list_templates():
    """List available workflow templates."""
    from src.workflows.engine import WorkflowEngine
    engine = WorkflowEngine()
    return {"templates": engine.list_templates()}


@router.get("/plugins")
async def list_plugins():
    """List registered plugins."""
    from src.workflows.engine import PluginRegistry
    registry = PluginRegistry()
    return {"plugins": registry.list_plugins()}
