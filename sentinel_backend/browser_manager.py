"""
Sentinel Backend - Secure Browser Manager
==========================================
The Core Engine - SecureBrowserSession

Responsibilities:
- Manage Playwright lifecycle
- Screenshot streaming (500ms)
- Latency tracking
- Crash recovery & restart
- WebSocket-safe operations
- Time-travel replay buffer
"""

import asyncio
import base64
import time
from typing import Optional, Dict, Any, List
from collections import deque
from playwright.async_api import async_playwright, Browser, Page, Playwright

from security_modules import (
    inject_honeypot,
    shadow_dom_xray,
    assess_action_risk,
    verify_visual_element,
)


class SecureBrowserSession:
    """
    Secure browser session with integrated security defenses.
    
    Each session manages:
    - Playwright browser instance
    - Real-time screenshot streaming
    - Security honeypot injection
    - Threat level monitoring
    - Forensic replay buffer
    """
    
    def __init__(self, websocket, client_id: str):
        self.websocket = websocket
        self.client_id = client_id
        
        # Playwright instances
        self.playwright: Optional[Playwright] = None
        self.browser: Optional[Browser] = None
        self.page: Optional[Page] = None
        
        # State
        self.running = True
        self.latency_ms = 0
        self.global_threat_level = 1  # DEFCON 1-5 (1=safe, 5=critical)
        self.current_url = ""
        self.action_count = 0
        
        # Time-Travel replay buffer (last 30 seconds ≈ 60 frames @ 500ms)
        self.replay_buffer: deque = deque(maxlen=60)
        
        # Visited URLs for audit trail
        self.visited_urls: List[str] = []
        
        # Threats detected
        self.threats_blocked = 0
    
    async def start(self):
        """Initialize browser and start screenshot streaming"""
        await self._launch_browser()
        asyncio.create_task(self._stream_screenshots())
    
    async def _launch_browser(self):
        """Launch Playwright browser with security hooks"""
        try:
            self.playwright = await async_playwright().start()
            
            # Launch headed browser for demos, headless for production
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=['--disable-web-security']  # For demo cross-origin access
            )
            
            context = await self.browser.new_context(
                viewport={'width': 1280, 'height': 720}
            )
            self.page = await context.new_page()
            
            # Inject honeypot traps BEFORE any page loads
            await inject_honeypot(self.page, self._honeypot_triggered)
            
            await self.websocket.send_json({
                "type": "BROWSER_READY",
                "client_id": self.client_id,
                "meta": self._meta()
            })
            
        except Exception as e:
            await self._handle_crash(f"Browser launch failed: {str(e)}")
    
    async def navigate(self, url: str) -> Dict[str, Any]:
        """Navigate to URL with latency tracking"""
        if not self.page:
            return {"error": "Browser not initialized"}
        
        start = time.time()
        
        try:
            await self.page.goto(url, wait_until='domcontentloaded', timeout=30000)
            self.latency_ms = int((time.time() - start) * 1000)
            self.current_url = url
            self.visited_urls.append(url)
            
            # Auto-scan after navigation
            xray_results = await shadow_dom_xray(self.page)
            hidden_threats = len(xray_results)
            
            if hidden_threats > 0:
                self.global_threat_level = min(self.global_threat_level + 1, 4)
                self.threats_blocked += hidden_threats
            
            await self.websocket.send_json({
                "type": "PAGE_LOADED",
                "url": url,
                "hidden_content_found": hidden_threats,
                "meta": self._meta()
            })
            
            return {
                "success": True,
                "url": url,
                "latency_ms": self.latency_ms,
                "threats_found": hidden_threats
            }
            
        except Exception as e:
            await self._handle_crash(f"Navigation failed: {str(e)}")
            return {"error": str(e)}
    
    async def click(self, selector: str, goal: str = "") -> Dict[str, Any]:
        """Click element with security interception"""
        if not self.page:
            return {"error": "Browser not initialized"}
        
        # Security check before action
        if goal:
            risk = await assess_action_risk(goal, f"click on {selector}")
            
            if risk["risk"] == "HIGH":
                self.global_threat_level = max(self.global_threat_level, 4)
                self.threats_blocked += 1
                
                await self.websocket.send_json({
                    "type": "ACTION_BLOCKED",
                    "action": "click",
                    "selector": selector,
                    "risk": risk,
                    "meta": self._meta()
                })
                
                return {
                    "success": False,
                    "blocked": True,
                    "reason": risk["reason"]
                }
        
        try:
            start = time.time()
            await self.page.click(selector, timeout=5000)
            self.latency_ms = int((time.time() - start) * 1000)
            self.action_count += 1
            
            return {
                "success": True,
                "action": "click",
                "selector": selector,
                "latency_ms": self.latency_ms
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    async def type_text(self, selector: str, text: str) -> Dict[str, Any]:
        """Type text into element"""
        if not self.page:
            return {"error": "Browser not initialized"}
        
        try:
            start = time.time()
            await self.page.fill(selector, text)
            self.latency_ms = int((time.time() - start) * 1000)
            self.action_count += 1
            
            return {
                "success": True,
                "action": "type",
                "selector": selector,
                "latency_ms": self.latency_ms
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    async def perform_xray_scan(self) -> Dict[str, Any]:
        """Execute Shadow DOM X-Ray scan"""
        if not self.page:
            return {"error": "Browser not initialized"}
        
        start = time.time()
        results = await shadow_dom_xray(self.page)
        self.latency_ms = int((time.time() - start) * 1000)
        
        await self.websocket.send_json({
            "type": "XRAY_RESULTS",
            "data": results,
            "count": len(results),
            "meta": self._meta()
        })
        
        return {
            "findings": results,
            "count": len(results),
            "latency_ms": self.latency_ms
        }
    
    async def intercept_action(self, goal: str, action: str) -> bool:
        """
        Semantic firewall check before any action.
        
        Returns True if action is allowed, False if blocked.
        """
        decision = await assess_action_risk(goal, action)
        
        if decision["risk"] == "HIGH":
            self.global_threat_level = max(self.global_threat_level, 4)
            self.threats_blocked += 1
            
            await self.websocket.send_json({
                "type": "RISK_ALERT",
                "decision": decision,
                "meta": self._meta()
            })
            
            return False
        
        return True
    
    async def verify_element(self, selector: str, expected_text: str = None) -> Dict[str, Any]:
        """Verify element exists (hallucination detection)"""
        if not self.page:
            return {"error": "Browser not initialized"}
        
        return await verify_visual_element(self.page, selector, expected_text)
    
    async def _stream_screenshots(self):
        """Stream screenshots every 500ms for real-time view"""
        while self.running:
            try:
                if self.page:
                    # Capture screenshot
                    screenshot = await self.page.screenshot(type="jpeg", quality=60)
                    encoded = base64.b64encode(screenshot).decode()
                    
                    payload = {
                        "type": "SCREENSHOT",
                        "image": encoded,
                        "url": self.current_url,
                        "meta": self._meta()
                    }
                    
                    # Add to replay buffer (time-travel)
                    self.replay_buffer.append({
                        **payload,
                        "timestamp": time.time()
                    })
                    
                    await self.websocket.send_json(payload)
                
                await asyncio.sleep(0.5)  # 500ms interval
                
            except Exception as e:
                await self._handle_crash(f"Screenshot stream error: {str(e)}")
                break
    
    async def _honeypot_triggered(self):
        """Handle honeypot trap activation - CRITICAL THREAT"""
        self.global_threat_level = 5  # Maximum threat
        self.running = False
        self.threats_blocked += 1
        
        await self.websocket.send_json({
            "type": "CRITICAL_THREAT",
            "reason": "Honey-Prompt Trap Triggered - Agent Compromised",
            "action": "SESSION_TERMINATED",
            "meta": self._meta()
        })
        
        # Terminate session
        await self.stop()
    
    async def _handle_crash(self, reason: str):
        """Handle browser crash with auto-recovery"""
        await self.websocket.send_json({
            "type": "SYSTEM_REBOOT",
            "reason": reason,
            "meta": self._meta()
        })
        
        # Attempt recovery
        try:
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
            
            # Relaunch
            await self._launch_browser()
            
        except Exception as e:
            self.running = False
            await self.websocket.send_json({
                "type": "FATAL_ERROR",
                "reason": f"Recovery failed: {str(e)}",
                "meta": self._meta()
            })
    
    async def stop(self):
        """Gracefully stop the browser session"""
        self.running = False
        
        try:
            if self.page:
                await self.page.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
        except:
            pass
        
        await self.websocket.send_json({
            "type": "SESSION_ENDED",
            "client_id": self.client_id,
            "stats": {
                "urls_visited": len(self.visited_urls),
                "actions_performed": self.action_count,
                "threats_blocked": self.threats_blocked
            },
            "meta": self._meta()
        })
    
    def get_replay_buffer(self) -> List[Dict]:
        """Get time-travel replay buffer for forensics"""
        return list(self.replay_buffer)
    
    def _meta(self) -> Dict[str, Any]:
        """Generate metadata for all messages"""
        return {
            "latency_ms": self.latency_ms,
            "defcon": self.global_threat_level,
            "threats_blocked": self.threats_blocked,
            "action_count": self.action_count,
            "timestamp": time.time()
        }


# ============================================
# SESSION POOL
# ============================================

class BrowserSessionPool:
    """Manage multiple browser sessions"""
    
    def __init__(self, max_sessions: int = 10):
        self.max_sessions = max_sessions
        self.sessions: Dict[str, SecureBrowserSession] = {}
    
    async def create_session(self, websocket, client_id: str) -> SecureBrowserSession:
        """Create and start new session"""
        if len(self.sessions) >= self.max_sessions:
            raise Exception("Maximum sessions reached")
        
        session = SecureBrowserSession(websocket, client_id)
        await session.start()
        self.sessions[client_id] = session
        
        return session
    
    def get_session(self, client_id: str) -> Optional[SecureBrowserSession]:
        """Get existing session"""
        return self.sessions.get(client_id)
    
    async def close_session(self, client_id: str):
        """Close and remove session"""
        if session := self.sessions.pop(client_id, None):
            await session.stop()
    
    async def close_all(self):
        """Close all sessions"""
        for client_id in list(self.sessions.keys()):
            await self.close_session(client_id)


# Global session pool
session_pool = BrowserSessionPool()
