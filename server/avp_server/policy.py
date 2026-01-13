from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


def _mode_allows(allowed: str, requested: str) -> Optional[str]:
    allowed = allowed or "both"
    requested = requested or "both"
    if allowed == "both":
        return requested
    # allowed is strict
    if requested != allowed:
        return allowed if requested == "both" else None
    return requested


def intersect_capabilities(requested: List[Dict[str, Any]], allowed: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Intersect requested capabilities with allowed template.

    Rules:
    - service and environment must match exactly
    - requested scopes must be subset of allowed scopes
    - mode must be constrained by allowed mode
    - resource handling: if allowed has resource, requested must match exactly;
      if allowed has no resource, requested must be null

    Label Binding (AVP-010):
    The 'resource' field in a capability maps to the 'label' field in the secrets table.
    When resolving secrets or making proxy calls, if resource is present, the server
    selects the secret matching (service, environment, label=resource) exactly.
    If resource is None and AVP_ALLOW_LABEL_FALLBACK is False (default), the server
    rejects the request. This ensures agents can only access specifically labeled secrets.
    """
    granted: List[Dict[str, Any]] = []
    allowed_index: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for a in allowed:
        key = (a.get("service"), a.get("environment"))
        allowed_index.setdefault(key, []).append(a)

    for r in requested:
        svc = r.get("service")
        env = r.get("environment")
        key = (svc, env)
        candidates = allowed_index.get(key, [])
        if not candidates:
            continue

        r_scopes = set(r.get("scopes") or [])
        r_mode = r.get("mode") or "both"
        r_res = r.get("resource")

        for a in candidates:
            a_scopes = set(a.get("scopes") or [])
            if not r_scopes.issubset(a_scopes):
                continue

            a_mode = a.get("mode") or "both"
            mode = _mode_allows(a_mode, r_mode)
            if mode is None:
                continue

            a_res = a.get("resource")
            if a_res is not None:
                if r_res != a_res:
                    continue
                resource = r_res
            else:
                # safer for v1: do not allow arbitrary resource if template did not specify one
                if r_res is not None:
                    continue
                resource = None

            granted.append({
                "service": svc,
                "scopes": sorted(list(r_scopes)),
                "environment": env,
                "resource": resource,
                "mode": mode
            })
            break

    return granted
