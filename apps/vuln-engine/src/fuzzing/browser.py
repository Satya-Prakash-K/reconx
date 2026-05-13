"""Browser Instrumentation — Playwright-based headless browser testing.

Supports:
- DOM-based XSS detection
- Client-side JS analysis
- Screenshot/video capture for evidence
- Cookie manipulation
- WebSocket interception
- Authenticated browsing sessions
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

import structlog

logger = structlog.get_logger(__name__)


class BrowserPool:
    """Manages a pool of headless browser instances for concurrent testing."""

    def __init__(self, pool_size: int = 5):
        self.pool_size = pool_size
        self._browsers: list = []
        self._playwright = None
        self._semaphore = asyncio.Semaphore(pool_size)

    async def init(self):
        """Initialize Playwright and browser pool."""
        from playwright.async_api import async_playwright
        self._playwright = await async_playwright().start()
        for _ in range(self.pool_size):
            browser = await self._playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox",
                      "--disable-dev-shm-usage", "--disable-gpu"],
            )
            self._browsers.append(browser)
        logger.info("Browser pool initialized", size=self.pool_size)

    async def execute(self, task: "BrowserTask") -> dict[str, Any]:
        """Execute a browser task using a pool slot."""
        async with self._semaphore:
            browser = self._browsers[0]  # Round-robin could be added
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconX/0.1",
            )

            if task.cookies:
                await context.add_cookies(task.cookies)

            page = await context.new_page()
            result: dict[str, Any] = {}

            try:
                # Set up interception
                responses_captured: list[dict] = []
                page.on("response", lambda r: responses_captured.append({
                    "url": r.url, "status": r.status,
                    "headers": dict(r.headers) if hasattr(r, 'headers') else {},
                }))

                # Navigate
                response = await page.goto(task.url, wait_until="networkidle", timeout=30000)

                result["status_code"] = response.status if response else 0
                result["final_url"] = page.url
                result["title"] = await page.title()

                # DOM analysis
                if task.check_dom_xss:
                    dom_findings = await self._check_dom_xss(page, task)
                    result["dom_xss"] = dom_findings

                # Screenshot for evidence
                if task.capture_screenshot:
                    screenshot = await page.screenshot(full_page=True)
                    result["screenshot"] = screenshot

                # Execute custom JavaScript
                if task.custom_js:
                    js_result = await page.evaluate(task.custom_js)
                    result["js_result"] = js_result

                # Capture console errors
                console_messages: list[str] = []
                page.on("console", lambda msg: console_messages.append(
                    f"[{msg.type}] {msg.text}"
                ))

                result["console"] = console_messages
                result["responses"] = responses_captured[:50]

            except Exception as e:
                result["error"] = str(e)
                logger.debug("Browser task failed", url=task.url, error=str(e))
            finally:
                await page.close()
                await context.close()

            return result

    async def _check_dom_xss(self, page, task: "BrowserTask") -> list[dict]:
        """Check for DOM-based XSS vulnerabilities."""
        findings: list[dict] = []

        # Inject test payloads into common DOM sinks
        dom_sinks = [
            "document.location", "document.URL", "document.referrer",
            "window.name", "location.hash", "location.search",
        ]

        # Check for dangerous sink usage
        dangerous_patterns = await page.evaluate("""
            () => {
                const patterns = [];
                const scripts = document.querySelectorAll('script');
                scripts.forEach(s => {
                    const text = s.textContent || '';
                    const sinks = ['innerHTML', 'outerHTML', 'document.write',
                                   'eval(', 'setTimeout(', 'setInterval(',
                                   '.src=', '.href=', '.action='];
                    sinks.forEach(sink => {
                        if (text.includes(sink)) {
                            patterns.push({sink: sink, context: text.substring(
                                Math.max(0, text.indexOf(sink) - 50),
                                text.indexOf(sink) + 100
                            )});
                        }
                    });
                });
                return patterns;
            }
        """)

        for pattern in dangerous_patterns:
            findings.append({
                "title": f"Potential DOM XSS sink: {pattern['sink']}",
                "description": f"Dangerous JavaScript sink found: {pattern['sink']}",
                "severity": "medium",
                "category": "xss",
                "evidence": {"sink": pattern["sink"], "context": pattern.get("context", "")[:200]},
                "confidence": 0.6,
                "source_tool": "browser_instrumentation",
            })

        return findings

    async def close(self):
        """Close all browsers and Playwright."""
        for browser in self._browsers:
            await browser.close()
        if self._playwright:
            await self._playwright.stop()
        logger.info("Browser pool closed")


class BrowserTask:
    """A task to execute in a headless browser."""

    def __init__(self, url: str, check_dom_xss: bool = True,
                 capture_screenshot: bool = False, custom_js: str | None = None,
                 cookies: list[dict] | None = None, auth_headers: dict | None = None):
        self.url = url
        self.check_dom_xss = check_dom_xss
        self.capture_screenshot = capture_screenshot
        self.custom_js = custom_js
        self.cookies = cookies or []
        self.auth_headers = auth_headers or {}
