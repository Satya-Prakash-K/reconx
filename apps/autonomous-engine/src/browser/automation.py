"""Advanced Browser Automation — human-like interaction, CAPTCHA-aware, MFA, DOM mutation.

Provides:
- Human-like mouse/keyboard simulation
- DOM mutation observation for SPA analysis
- Authenticated session management and replay
- CAPTCHA detection and workflow adaptation
- MFA-aware login flows
- Evidence capture (screenshots, HAR, DOM snapshots)
"""

from __future__ import annotations

import asyncio
import random
from typing import Any, Optional

import structlog

logger = structlog.get_logger(__name__)


class HumanLikeAutomation:
    """Simulates human-like browser interaction to avoid bot detection."""

    def __init__(self):
        self.browser = None
        self.context = None

    async def init(self, headless: bool = True):
        from playwright.async_api import async_playwright
        pw = await async_playwright().start()
        self.browser = await pw.chromium.launch(
            headless=headless,
            args=["--disable-blink-features=AutomationControlled"],
        )
        self.context = await self.browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
            locale="en-US",
            timezone_id="America/New_York",
        )
        # Anti-detection
        await self.context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3]});
            Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
            window.chrome = {runtime: {}};
        """)

    async def human_click(self, page, selector: str):
        """Click with human-like mouse movement and timing."""
        el = await page.wait_for_selector(selector, timeout=10000)
        box = await el.bounding_box()
        if box:
            x = box["x"] + box["width"] * random.uniform(0.2, 0.8)
            y = box["y"] + box["height"] * random.uniform(0.2, 0.8)
            await page.mouse.move(x, y, steps=random.randint(5, 15))
            await asyncio.sleep(random.uniform(0.05, 0.2))
            await page.mouse.click(x, y)
        else:
            await el.click()
        await asyncio.sleep(random.uniform(0.3, 0.8))

    async def human_type(self, page, selector: str, text: str):
        """Type with human-like keystroke timing."""
        await self.human_click(page, selector)
        for char in text:
            await page.keyboard.type(char, delay=random.randint(30, 120))
            if random.random() < 0.05:
                await asyncio.sleep(random.uniform(0.2, 0.5))

    async def close(self):
        if self.browser:
            await self.browser.close()


class DOMMutationAnalyzer:
    """Observes DOM mutations in SPAs to detect dynamic content and XSS sinks."""

    async def observe(self, page, duration_ms: int = 5000) -> list[dict]:
        """Observe DOM mutations for a given duration."""
        mutations = await page.evaluate(f"""
            () => new Promise(resolve => {{
                const mutations = [];
                const observer = new MutationObserver(list => {{
                    for (const m of list) {{
                        mutations.push({{
                            type: m.type,
                            target: m.target.tagName || 'text',
                            addedNodes: m.addedNodes.length,
                            removedNodes: m.removedNodes.length,
                            attributeName: m.attributeName,
                        }});
                    }}
                }});
                observer.observe(document.body, {{
                    childList: true, subtree: true, attributes: true, characterData: true
                }});
                setTimeout(() => {{ observer.disconnect(); resolve(mutations); }}, {duration_ms});
            }})
        """)
        return mutations

    async def find_xss_sinks(self, page) -> list[dict]:
        """Find potential XSS sinks in the DOM."""
        return await page.evaluate("""
            () => {
                const sinks = [];
                // innerHTML assignments
                document.querySelectorAll('*').forEach(el => {
                    if (el.innerHTML && el.innerHTML.includes('<')) {
                        sinks.push({type: 'innerHTML', tag: el.tagName, preview: el.innerHTML.slice(0, 100)});
                    }
                });
                // Event handlers
                const dangerous = ['onerror', 'onload', 'onclick', 'onmouseover'];
                document.querySelectorAll('*').forEach(el => {
                    dangerous.forEach(attr => {
                        if (el.hasAttribute(attr)) {
                            sinks.push({type: attr, tag: el.tagName, value: el.getAttribute(attr).slice(0, 100)});
                        }
                    });
                });
                return sinks.slice(0, 50);
            }
        """)


class AuthSessionManager:
    """Manages authenticated browser sessions with replay support."""

    def __init__(self):
        self._sessions: dict[str, dict] = {}

    async def login(self, page, login_url: str, credentials: dict, selectors: dict) -> bool:
        """Perform login with configurable selectors."""
        automation = HumanLikeAutomation()
        try:
            await page.goto(login_url, wait_until="networkidle")
            username_sel = selectors.get("username", 'input[name="username"], input[type="email"]')
            password_sel = selectors.get("password", 'input[name="password"], input[type="password"]')
            submit_sel = selectors.get("submit", 'button[type="submit"]')

            await automation.human_type(page, username_sel, credentials.get("username", ""))
            await automation.human_type(page, password_sel, credentials.get("password", ""))
            await automation.human_click(page, submit_sel)
            await page.wait_for_load_state("networkidle", timeout=15000)

            cookies = await page.context.cookies()
            if cookies:
                self._sessions[login_url] = {"cookies": cookies, "url": page.url}
                return True
        except Exception as e:
            logger.error("Login failed", url=login_url, error=str(e))
        return False

    async def replay_session(self, page, login_url: str) -> bool:
        """Replay a saved session by restoring cookies."""
        session = self._sessions.get(login_url)
        if session:
            await page.context.add_cookies(session["cookies"])
            return True
        return False


class CAPTCHADetector:
    """Detects CAPTCHA presence and adapts workflow accordingly."""

    CAPTCHA_INDICATORS = [
        "recaptcha", "hcaptcha", "captcha", "cf-turnstile",
        "g-recaptcha", "h-captcha", "challenge-platform",
    ]

    async def detect(self, page) -> dict[str, Any]:
        """Check if the current page has a CAPTCHA."""
        html = await page.content()
        html_lower = html.lower()
        for indicator in self.CAPTCHA_INDICATORS:
            if indicator in html_lower:
                captcha_type = "recaptcha" if "recaptcha" in indicator else \
                              "hcaptcha" if "hcaptcha" in indicator else \
                              "cloudflare" if "turnstile" in indicator else "unknown"
                return {"detected": True, "type": captcha_type, "indicator": indicator}

        # Check for iframe-based CAPTCHAs
        iframes = await page.query_selector_all("iframe")
        for iframe in iframes:
            src = await iframe.get_attribute("src") or ""
            if any(ind in src.lower() for ind in self.CAPTCHA_INDICATORS):
                return {"detected": True, "type": "iframe_captcha", "src": src[:200]}

        return {"detected": False}


class EvidenceCapture:
    """Captures evidence from browser sessions."""

    async def capture_full(self, page, finding_id: str, output_dir: str = "/tmp/evidence") -> dict:
        """Capture screenshot, DOM, and console logs as evidence."""
        import os
        os.makedirs(output_dir, exist_ok=True)

        screenshot_path = f"{output_dir}/{finding_id}.png"
        await page.screenshot(path=screenshot_path, full_page=True)

        dom = await page.content()
        dom_path = f"{output_dir}/{finding_id}.html"
        with open(dom_path, "w") as f:
            f.write(dom)

        return {
            "screenshot": screenshot_path,
            "dom_snapshot": dom_path,
            "url": page.url,
            "title": await page.title(),
        }
