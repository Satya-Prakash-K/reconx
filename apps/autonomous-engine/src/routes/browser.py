"""Browser automation API routes."""

from __future__ import annotations
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class BrowserScanRequest(BaseModel):
    url: str
    wait_ms: int = 5000


class LoginRequest(BaseModel):
    login_url: str
    username: str
    password: str
    selectors: dict = {}


@router.post("/dom-mutations")
async def observe_dom(request: BrowserScanRequest):
    """Observe DOM mutations on a page."""
    from src.browser.automation import HumanLikeAutomation, DOMMutationAnalyzer
    auto = HumanLikeAutomation()
    await auto.init()
    page = await auto.context.new_page()
    await page.goto(request.url, wait_until="networkidle")
    analyzer = DOMMutationAnalyzer()
    mutations = await analyzer.observe(page, request.wait_ms)
    sinks = await analyzer.find_xss_sinks(page)
    await auto.close()
    return {"mutations": len(mutations), "xss_sinks": sinks}


@router.post("/captcha-check")
async def check_captcha(request: BrowserScanRequest):
    """Check for CAPTCHA on a page."""
    from src.browser.automation import HumanLikeAutomation, CAPTCHADetector
    auto = HumanLikeAutomation()
    await auto.init()
    page = await auto.context.new_page()
    await page.goto(request.url, wait_until="networkidle")
    detector = CAPTCHADetector()
    result = await detector.detect(page)
    await auto.close()
    return result
