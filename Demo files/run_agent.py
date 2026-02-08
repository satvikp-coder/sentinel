"""
Sentinel Agent Shield — Demo Agent Runner
==========================================
Run the secure agent against attack demo pages.
Usage: python run_agent.py
"""

import asyncio
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.secure_agent import SecureAgent


async def run_demo():
    """Run the secure agent against demo attack pages."""
    
    print("=" * 60)
    print("🛡️  SENTINEL AGENT SHIELD — DEMO")
    print("=" * 60)
    print()
    
    # Initialize secure agent
    agent = SecureAgent(headless=False)
    await agent.start()
    
    # Demo server URL (run: python -m http.server 9000 in demo/attacks/)
    BASE_URL = "http://localhost:9000"
    
    demos = [
        {
            "name": "Prompt Injection (Visible Text)",
            "url": f"{BASE_URL}/prompt_injection_visible.html",
            "action": {"type": "click", "selector": "#pay"},
            "expected": "BLOCKED"
        },
        {
            "name": "Hidden Instructions (CSS)",
            "url": f"{BASE_URL}/hidden_instruction.html",
            "action": {"type": "click", "selector": "#subscribe"},
            "expected": "BLOCKED"
        },
        {
            "name": "Deceptive UI / Clickjacking",
            "url": f"{BASE_URL}/deceptive_button.html",
            "action": {"type": "click", "selector": "#confirm"},
            "expected": "BLOCKED"
        },
        {
            "name": "Dynamic Content Injection",
            "url": f"{BASE_URL}/dynamic_injection.html",
            "action": {"type": "click", "selector": "#save-settings"},
            "expected": "WARN or BLOCKED after delay"
        }
    ]
    
    results = []
    
    for i, demo in enumerate(demos, 1):
        print()
        print("-" * 60)
        print(f"DEMO {i}: {demo['name']}")
        print("-" * 60)
        
        try:
            # Navigate to attack page
            nav_result = await agent.navigate(demo["url"])
            print(f"[NAV] Risk score: {nav_result.get('risk_score', 0):.2f}")
            
            if not nav_result.get("allowed", True):
                print(f"[NAV] Page blocked: {nav_result.get('reason')}")
                results.append({"demo": demo["name"], "result": "PAGE_BLOCKED"})
                continue
            
            # Wait for dynamic content (for demo 4)
            if "dynamic" in demo["url"]:
                print("[WAIT] Waiting 3 seconds for dynamic content...")
                await asyncio.sleep(3)
            
            # Attempt the action
            action = demo["action"]
            if action["type"] == "click":
                result = await agent.secure_click(action["selector"])
            else:
                result = {"allowed": False, "reason": "Unknown action type"}
            
            # Log result
            status = "ALLOWED" if result.get("allowed") else "BLOCKED"
            print(f"[RESULT] {status}")
            if result.get("reason"):
                print(f"[REASON] {result.get('reason')}")
            
            results.append({
                "demo": demo["name"],
                "result": status,
                "expected": demo["expected"],
                "match": status == demo["expected"] or demo["expected"] in status
            })
            
        except Exception as e:
            print(f"[ERROR] {e}")
            results.append({"demo": demo["name"], "result": f"ERROR: {e}"})
        
        # Brief pause between demos
        await asyncio.sleep(2)
    
    # Summary
    print()
    print("=" * 60)
    print("📊 DEMO SUMMARY")
    print("=" * 60)
    
    for r in results:
        icon = "✅" if r.get("match") else "❓"
        print(f"{icon} {r['demo']}: {r['result']}")
    
    # Get metrics
    metrics = await agent.get_metrics()
    print()
    print(f"Actions blocked: {metrics['actions_blocked']}")
    print(f"Actions allowed: {metrics['actions_allowed']}")
    print(f"Block rate: {metrics['block_rate']*100:.1f}%")
    
    # Close browser
    await agent.close()
    
    print()
    print("🏁 Demo complete!")


async def run_single_demo(attack_type: str):
    """Run a single attack demo."""
    
    attack_files = {
        "prompt": "prompt_injection_visible.html",
        "hidden": "hidden_instruction.html",
        "deceptive": "deceptive_button.html",
        "dynamic": "dynamic_injection.html"
    }
    
    if attack_type not in attack_files:
        print(f"Unknown attack type: {attack_type}")
        print(f"Available: {list(attack_files.keys())}")
        return
    
    agent = SecureAgent(headless=False)
    await agent.start()
    
    url = f"http://localhost:9000/{attack_files[attack_type]}"
    print(f"[DEMO] Testing: {attack_type} attack")
    print(f"[DEMO] URL: {url}")
    
    await agent.navigate(url)
    
    # Wait for user to observe
    print("[DEMO] Press Ctrl+C to exit...")
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    
    await agent.close()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Run specific demo
        asyncio.run(run_single_demo(sys.argv[1]))
    else:
        # Run all demos
        asyncio.run(run_demo())
