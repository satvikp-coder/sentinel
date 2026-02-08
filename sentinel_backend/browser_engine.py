"""
Sentinel Backend - Secure Browser Engine
=========================================
Playwright-powered browser with security integrations.

Features:
- Headed Chromium browser
- Honeypot injection
- DOM extraction
- Screenshot streaming
- Action interception
"""

import asyncio
import base64
import time
from typing import Optional, Callable, Dict, Any, List
from dataclasses import dataclass, field
from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Playwright

from sentinel_backend.models import SessionConfig, SessionState, AgentState, WSEvent, ActionDecision
from sentinel_backend.utils import logger, now_iso, generate_session_id
from sentinel_backend.honey_prompt import generate_trap_config, check_honeypot_trigger, cleanup_session_traps
from sentinel_backend.shadow_dom_scanner import ShadowDOMScanner, DOM_EXTRACTION_SCRIPT
from sentinel_backend.security_engine import analyze_all_threats
from sentinel_backend.semantic_firewall import semantic_check
from sentinel_backend.policy_engine import evaluate_action, policy_store
from sentinel_backend.risk_scorer import calculate_risk_score, update_trust_score
from sentinel_backend.replay_buffer import replay_manager
from sentinel_backend.metrics_engine import metrics_engine
from sentinel_backend.report_engine import session_store, log_threat, log_action


# ============================================
# SECURE BROWSER CLASS
# ============================================

class SecureBrowser:
    """
    Security-wrapped Playwright browser.
    
    Handles:
    - Browser lifecycle
    - Action interception
    - Security scanning
    - Screenshot capture
    - Event emission
    """
    
    def __init__(
        self,
        session_id: str,
        config: SessionConfig,
        event_callback: Optional[Callable] = None
    ):
        self.session_id = session_id
        self.config = config
        self.event_callback = event_callback
        
        # State
        self.state = SessionState(
            session_id=session_id,
            state=AgentState.INITIALIZING,
            trust_score=100.0,
            risk_score=0.0
        )
        
        # Playwright objects
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        
        # Utilities
        self._scanner = ShadowDOMScanner()
        self._honeypot_config = None
        
        # Screenshot task
        self._screenshot_task: Optional[asyncio.Task] = None
        self._running = False
    
    # ==========================================
    # LIFECYCLE
    # ==========================================
    
    async def start(self):
        """Initialize browser and all security systems"""
        try:
            logger.info(f"[BROWSER] Starting session {self.session_id}")
            
            # Start Playwright
            self._playwright = await async_playwright().start()
            
            # Launch browser (headed for demos)
            self._browser = await self._playwright.chromium.launch(
                headless=self.config.headless,
                args=['--disable-web-security']  # For demo purposes
            )
            
            # Create context
            self._context = await self._browser.new_context(
                viewport={
                    'width': self.config.viewport_width,
                    'height': self.config.viewport_height
                }
            )
            
            # Create page
            self._page = await self._context.new_page()
            
            # Inject honeypot traps
            self._honeypot_config = generate_trap_config(self.session_id)
            await self._page.add_init_script(self._honeypot_config.injection_script)
            
            # Initialize tracking
            replay_manager.create_buffer(self.session_id)
            metrics_engine.start_session(self.session_id)
            session_store.create_session(
                self.session_id,
                target_url=self.config.target_url,
                task_goal=self.config.task_goal
            )
            
            # Update state
            self.state.state = AgentState.OBSERVING
            self._running = True
            
            await self._emit_event("SESSION_STARTED", {
                'session_id': self.session_id,
                'target_url': self.config.target_url
            })
            
            logger.info(f"[BROWSER] Session {self.session_id} started successfully")
            
        except Exception as e:
            logger.error(f"[BROWSER] Failed to start: {e}")
            self.state.state = AgentState.TERMINATED
            raise
    
    async def stop(self):
        """Cleanup browser and all resources"""
        self._running = False
        
        try:
            # Stop screenshot task
            if self._screenshot_task:
                self._screenshot_task.cancel()
            
            # Close browser
            if self._page:
                await self._page.close()
            if self._context:
                await self._context.close()
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
            
            # Update state
            self.state.state = AgentState.TERMINATED
            session_store.update_session(self.session_id, {
                'ended_at': now_iso(),
                'final_state': 'TERMINATED'
            })
            
            # Cleanup
            cleanup_session_traps(self.session_id)
            metrics_engine.end_session(self.session_id)
            
            await self._emit_event("SESSION_TERMINATED", {
                'session_id': self.session_id
            })
            
            logger.info(f"[BROWSER] Session {self.session_id} stopped")
            
        except Exception as e:
            logger.error(f"[BROWSER] Error during stop: {e}")
    
    # ==========================================
    # NAVIGATION
    # ==========================================
    
    async def navigate(self, url: str) -> Dict[str, Any]:
        """Navigate to URL with security checks"""
        if not self._page:
            return {'error': 'Browser not initialized'}
        
        start_time = time.perf_counter()
        
        try:
            self.state.state = AgentState.ACTING
            
            # Pre-navigation policy check
            policy_result = evaluate_action(
                {'type': 'NAVIGATE', 'url': url},
                {'trust_score': self.state.trust_score, 'session_id': self.session_id}
            )
            
            if not policy_result.allowed:
                latency = (time.perf_counter() - start_time) * 1000
                await self._emit_event("ACTION_BLOCKED", {
                    'action': 'NAVIGATE',
                    'url': url,
                    'reason': 'Policy violation'
                })
                return {
                    'success': False,
                    'blocked': True,
                    'reason': 'Navigation blocked by policy',
                    'latency_ms': latency
                }
            
            # Navigate
            await self._page.goto(url, wait_until='domcontentloaded', timeout=30000)
            
            self.state.current_url = url
            
            # Post-navigation scan
            dom = await self.extract_dom()
            scan_result = self._scanner.scan(dom)
            
            # Analyze threats
            detections = analyze_all_threats(
                dom_tree=dom,
                text_content=await self._page.content()
            )
            
            risk = calculate_risk_score(detections)
            self.state.risk_score = risk.total_score
            
            # Record snapshot
            screenshot = await self.capture_screenshot()
            replay_manager.add_snapshot(
                self.session_id,
                agent_state=self.state.state,
                current_url=url,
                dom_tree=dom,
                screenshot_b64=screenshot,
                risk_score=risk.total_score,
                trust_score=self.state.trust_score,
                active_threats=[t.get('type', 'UNKNOWN') for t in scan_result.threats]
            )
            
            self.state.state = AgentState.OBSERVING
            
            latency = (time.perf_counter() - start_time) * 1000
            
            await self._emit_event("PAGE_LOADED", {
                'url': url,
                'risk_score': risk.total_score,
                'threats': len(scan_result.threats)
            })
            
            # Log action
            log_action(self.session_id, {
                'type': 'NAVIGATE',
                'url': url,
                'risk_score': risk.total_score,
                'allowed': True
            })
            
            metrics_engine.record_action(
                self.session_id,
                allowed=True,
                blocked=False,
                latency_ms=latency,
                risk_score=risk.total_score,
                threats_detected=len(scan_result.threats)
            )
            
            return {
                'success': True,
                'url': url,
                'risk_score': risk.total_score,
                'threats_found': len(scan_result.threats),
                'scan_result': scan_result.model_dump(),
                'latency_ms': latency
            }
            
        except Exception as e:
            logger.error(f"[BROWSER] Navigation failed: {e}")
            self.state.state = AgentState.OBSERVING
            return {'error': str(e)}
    
    # ==========================================
    # ACTIONS
    # ==========================================
    
    async def click(
        self,
        selector: str,
        agent_intent: Optional[str] = None
    ) -> Dict[str, Any]:
        """Click element with security interception"""
        if not self._page:
            return {'error': 'Browser not initialized'}
        
        start_time = time.perf_counter()
        
        try:
            self.state.state = AgentState.ACTING
            action = {'type': 'CLICK', 'selector': selector}
            
            # Security evaluation
            decision, details = await self._evaluate_action(
                action=action,
                agent_intent=agent_intent
            )
            
            if decision == ActionDecision.BLOCK:
                self.state.state = AgentState.BLOCKED
                return {
                    'success': False,
                    'blocked': True,
                    'decision': 'BLOCK',
                    'details': details,
                    'latency_ms': (time.perf_counter() - start_time) * 1000
                }
            
            if decision == ActionDecision.REQUIRE_CONFIRMATION:
                await self._emit_event("CONFIRMATION_REQUIRED", {
                    'action': action,
                    'details': details
                })
                return {
                    'success': False,
                    'awaiting_confirmation': True,
                    'decision': 'REQUIRE_CONFIRMATION',
                    'details': details,
                    'latency_ms': (time.perf_counter() - start_time) * 1000
                }
            
            # Execute click
            await self._page.click(selector, timeout=5000)
            
            self.state.actions_count += 1
            self.state.state = AgentState.OBSERVING
            
            latency = (time.perf_counter() - start_time) * 1000
            
            # Log
            log_action(self.session_id, {
                'type': 'CLICK',
                'selector': selector,
                'intent': agent_intent,
                'allowed': True
            })
            
            metrics_engine.record_action(
                self.session_id,
                allowed=True,
                blocked=False,
                latency_ms=latency
            )
            
            return {
                'success': True,
                'action': 'CLICK',
                'selector': selector,
                'latency_ms': latency
            }
            
        except Exception as e:
            logger.error(f"[BROWSER] Click failed: {e}")
            self.state.state = AgentState.OBSERVING
            return {'error': str(e)}
    
    async def type_text(
        self,
        selector: str,
        text: str,
        agent_intent: Optional[str] = None
    ) -> Dict[str, Any]:
        """Type text with security interception"""
        if not self._page:
            return {'error': 'Browser not initialized'}
        
        start_time = time.perf_counter()
        
        try:
            self.state.state = AgentState.ACTING
            action = {'type': 'TYPE', 'selector': selector, 'text': text}
            
            decision, details = await self._evaluate_action(action, agent_intent)
            
            if decision == ActionDecision.BLOCK:
                self.state.state = AgentState.BLOCKED
                return {'success': False, 'blocked': True, 'details': details}
            
            # Execute type
            await self._page.fill(selector, text)
            
            self.state.actions_count += 1
            self.state.state = AgentState.OBSERVING
            
            return {
                'success': True,
                'action': 'TYPE',
                'selector': selector,
                'latency_ms': (time.perf_counter() - start_time) * 1000
            }
            
        except Exception as e:
            logger.error(f"[BROWSER] Type failed: {e}")
            return {'error': str(e)}
    
    # ==========================================
    # SECURITY EVALUATION
    # ==========================================
    
    async def _evaluate_action(
        self,
        action: Dict[str, Any],
        agent_intent: Optional[str] = None
    ) -> tuple:
        """
        Evaluate action through all security modules.
        
        Returns (decision, details)
        """
        details = {}
        
        # 1. Honeypot check
        honeypot = check_honeypot_trigger(
            self.session_id,
            {**action, 'agent_intent': agent_intent}
        )
        if honeypot.get('triggered'):
            self.state.state = AgentState.COMPROMISED
            await self._emit_event("HONEYPOT_TRIGGERED", honeypot)
            return (ActionDecision.BLOCK, honeypot)
        
        # 2. Semantic check
        if agent_intent:
            semantic = semantic_check(
                intent=agent_intent,
                action=f"{action.get('type')} on {action.get('selector', action.get('url', ''))}"
            )
            details['semantic'] = semantic.model_dump()
            
            if semantic.decision == ActionDecision.BLOCK:
                log_threat(self.session_id, {
                    'type': 'SEMANTIC_MISMATCH',
                    'divergence_score': semantic.divergence_score,
                    'reason': semantic.reason
                })
        
        # 3. Policy check
        policy = evaluate_action(
            action,
            {
                'trust_score': self.state.trust_score,
                'session_id': self.session_id,
                'current_url': self.state.current_url
            }
        )
        details['policy'] = policy.model_dump()
        
        # 4. Risk calculation
        risk = calculate_risk_score(
            {'semantic': details.get('semantic', {})},
            policy_result=policy
        )
        details['risk'] = risk.model_dump()
        
        # Update trust
        self.state.trust_score = update_trust_score(
            self.state.trust_score,
            risk.total_score
        )
        self.state.risk_score = risk.total_score
        
        # Emit risk update
        await self._emit_event("RISK_UPDATE", {
            'risk_score': risk.total_score,
            'trust_score': self.state.trust_score
        })
        
        return (risk.decision, details)
    
    # ==========================================
    # DOM & SCREENSHOTS
    # ==========================================
    
    async def extract_dom(self) -> Dict[str, Any]:
        """Extract full DOM including shadow roots"""
        if not self._page:
            return {}
        
        try:
            return await self._page.evaluate(DOM_EXTRACTION_SCRIPT)
        except Exception as e:
            logger.error(f"[BROWSER] DOM extraction failed: {e}")
            return {}
    
    async def capture_screenshot(self) -> str:
        """Capture screenshot as base64"""
        if not self._page:
            return ""
        
        try:
            screenshot = await self._page.screenshot(type='jpeg', quality=70)
            return base64.b64encode(screenshot).decode('utf-8')
        except Exception as e:
            logger.error(f"[BROWSER] Screenshot failed: {e}")
            return ""
    
    async def start_screenshot_streaming(self, interval_ms: int = 500):
        """Start streaming screenshots at interval"""
        async def stream():
            while self._running:
                try:
                    screenshot = await self.capture_screenshot()
                    if screenshot:
                        await self._emit_event("SCREENSHOT", {'data': screenshot})
                    await asyncio.sleep(interval_ms / 1000)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"[BROWSER] Screenshot stream error: {e}")
        
        self._screenshot_task = asyncio.create_task(stream())
    
    # ==========================================
    # UTILITY
    # ==========================================
    
    async def _emit_event(self, event_type: str, data: Dict[str, Any] = None):
        """Emit event to callback"""
        if self.event_callback:
            event = WSEvent(type=event_type, data=data or {})
            try:
                await self.event_callback(event.model_dump())
            except Exception as e:
                logger.error(f"[BROWSER] Event emission failed: {e}")
    
    def get_state(self) -> Dict[str, Any]:
        """Get current session state"""
        return self.state.model_dump()


# ============================================
# BROWSER POOL
# ============================================

class BrowserPool:
    """
    Manages multiple browser sessions.
    
    Prevents resource exhaustion and manages lifecycle.
    """
    
    def __init__(self, max_sessions: int = 10):
        self.max_sessions = max_sessions
        self._sessions: Dict[str, SecureBrowser] = {}
    
    async def create_session(
        self,
        config: SessionConfig,
        event_callback: Optional[Callable] = None
    ) -> SecureBrowser:
        """Create new browser session"""
        if len(self._sessions) >= self.max_sessions:
            raise Exception("Maximum sessions reached")
        
        session_id = generate_session_id()
        browser = SecureBrowser(session_id, config, event_callback)
        
        await browser.start()
        self._sessions[session_id] = browser
        
        return browser
    
    def get_session(self, session_id: str) -> Optional[SecureBrowser]:
        """Get existing session"""
        return self._sessions.get(session_id)
    
    async def close_session(self, session_id: str):
        """Close and cleanup session"""
        if browser := self._sessions.pop(session_id, None):
            await browser.stop()
    
    async def close_all(self):
        """Close all sessions"""
        for session_id in list(self._sessions.keys()):
            await self.close_session(session_id)


# Global browser pool
browser_pool = BrowserPool()
