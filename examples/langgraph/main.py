from __future__ import annotations

import os
import json
import httpx


def main():
    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")

    if not api_key:
        print("Missing OPENAI_API_KEY. Run via AVP CLI:")
        print("  avp run --agent-id <id> --resource default -- python examples/langgraph/main.py")
        print("")
        print("Make sure you have created a secret with matching label:")
        print("  avp add-secret --service openai --label default --api-key sk-...")
        return

    url = base_url.rstrip("/") + "/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "Say hello from AVP"}],
        "temperature": 0.2
    }

    print("Calling OpenAI via env injected key...")
    with httpx.Client(timeout=30.0) as client:
        resp = client.post(url, headers=headers, json=payload)
        print("Status:", resp.status_code)
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text}
        print(json.dumps(data, indent=2)[:2000])


if __name__ == "__main__":
    main()
