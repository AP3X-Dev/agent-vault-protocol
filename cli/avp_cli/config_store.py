from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


def config_path() -> Path:
    base = Path(os.environ.get("AVP_CONFIG_DIR") or (Path.home() / ".config" / "avp"))
    base.mkdir(parents=True, exist_ok=True)
    return base / "config.json"


def load_config() -> Dict[str, Any]:
    p = config_path()
    if not p.exists():
        return {"url": None, "principal_token": None, "agents": {}}
    return json.loads(p.read_text(encoding="utf-8"))


def save_config(cfg: Dict[str, Any]) -> None:
    p = config_path()
    p.write_text(json.dumps(cfg, indent=2, sort_keys=True), encoding="utf-8")


def get_agent_token(cfg: Dict[str, Any], agent_id: str) -> Optional[str]:
    agents = cfg.get("agents") or {}
    info = agents.get(agent_id) or {}
    return info.get("agent_token")


def set_agent_token(cfg: Dict[str, Any], agent_id: str, token: str) -> None:
    cfg.setdefault("agents", {})
    cfg["agents"].setdefault(agent_id, {})
    cfg["agents"][agent_id]["agent_token"] = token
