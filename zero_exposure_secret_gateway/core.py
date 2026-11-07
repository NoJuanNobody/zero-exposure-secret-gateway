import getpass
import hashlib
import re
import subprocess
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


KNOWN_SECRET_PATTERNS = [
    ("OPENAI_API_KEY", ["openai", "gpt", "whisper", "realtime api"]),
    ("ANTHROPIC_API_KEY", ["anthropic", "claude"]),
    ("GEMINI_API_KEY", ["gemini", "google ai", "vertex"]),
    ("STRIPE_SECRET_KEY", ["stripe", "billing", "payment", "checkout"]),
    ("CLERK_SECRET_KEY", ["clerk", "auth", "session"]),
    ("SUPABASE_SERVICE_ROLE_KEY", ["supabase", "postgres service role"]),
    ("TWILIO_AUTH_TOKEN", ["twilio", "sms", "voice call", "sip"]),
    ("ELEVENLABS_API_KEY", ["elevenlabs", "tts", "voice clone"]),
    ("DATABASE_URL", ["database", "postgres", "neon", "db url"]),
    ("REDIS_URL", ["redis", "upstash", "cache"]),
    ("GITHUB_TOKEN", ["github", "gh token", "repo access"]),
]

LEAK_REGEXES = [
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("STRIPE_KEY", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("GITHUB_PAT", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b")),
]


def resolve_secret_intent(
    description: str,
    explicit_key: Optional[str] = None,
    project: Optional[str] = None,
    service: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Conversational wrapper: maps a natural-language description of what the user
    is building and which hosted app needs a secret into canonical environment variable keys.
    """
    if explicit_key:
        clean_key = re.sub(r"[^A-Za-z0-9_]", "_", explicit_key.strip().upper())
        return {
            "project": project or "default-railway-project",
            "service": service,
            "recommended_key": clean_key,
            "candidate_keys": [clean_key],
            "confidence": 1.0,
            "description": description,
        }

    desc_lower = description.lower()
    matched_keys: List[str] = []

    for env_key, keywords in KNOWN_SECRET_PATTERNS:
        if any(kw in desc_lower for kw in keywords):
            matched_keys.append(env_key)

    if not matched_keys:
        # Derive a sensible key name from the description or fallback
        tokens = re.findall(r"[a-zA-Z0-9]+", description.upper())
        stop = {"I", "NEED", "TO", "SET", "ADD", "THE", "FOR", "MY", "ON", "IN", "A", "AN", "KEY", "SECRET", "API"}
        meaningful = [t for t in tokens if t not in stop][:2]
        derived = "_".join(meaningful + ["API_KEY"]) if meaningful else "APP_SECRET_KEY"
        matched_keys.append(derived)

    return {
        "project": project or "default-railway-project",
        "service": service,
        "recommended_key": matched_keys[0],
        "candidate_keys": matched_keys,
        "confidence": 0.95 if len(matched_keys) >= 1 else 0.6,
        "description": description,
    }


def compute_secret_receipt(secret_value: str) -> Dict[str, Any]:
    """
    Computes a zero-exposure receipt (truncated SHA-256 hash and length metadata)
    that can be safely logged in an LLM chat trajectory without exposing the secret.
    """
    digest = hashlib.sha256(secret_value.encode("utf-8")).hexdigest()
    return {
        "fingerprint": f"sha256:{digest[:12]}",
        "length": len(secret_value),
        "verified_non_empty": len(secret_value.strip()) > 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def scan_and_redact_trajectory(text: str) -> Dict[str, Any]:
    """
    Scans a chat prompt or trajectory string for raw API keys/secrets and redacts them
    before they reach model servers or persistent transcript logs.
    """
    redacted = text
    detections: List[Dict[str, str]] = []

    for label, pattern in LEAK_REGEXES:
        for match in pattern.finditer(text):
            raw = match.group(0)
            receipt = compute_secret_receipt(raw)
            replacement = f"<REDACTED_{label}:{receipt['fingerprint']}>"
            redacted = redacted.replace(raw, replacement)
            detections.append({
                "type": label,
                "fingerprint": receipt["fingerprint"],
                "length": str(receipt["length"]),
            })

    return {
        "has_leaks": len(detections) > 0,
        "leak_count": len(detections),
        "detections": detections,
        "redacted_text": redacted,
    }


def inject_secret_to_provider(
    key: str,
    secret_value: Optional[str] = None,
    project: Optional[str] = None,
    service: Optional[str] = None,
    environment: Optional[str] = None,
    provider: str = "railway",
    dry_run: bool = False,
    prompt_fn: Optional[Callable[[str], str]] = None,
) -> Dict[str, Any]:
    """
    Collects the secret value via hidden console input (getpass) if not provided,
    and injects it directly into Railway (or another cloud provider CLI) using subprocess
    without exposing the secret value in stdout or LLM chat trajectories.
    """
    if secret_value is None:
        reader = prompt_fn or getpass.getpass
        prompt_label = f"[Zero-Exposure Gateway] Paste secret for {key} (input is hidden): "
        secret_value = reader(prompt_label)

    if not secret_value or not secret_value.strip():
        raise ValueError(f"Secret value for '{key}' cannot be empty.")

    receipt = compute_secret_receipt(secret_value)

    if provider == "railway":
        cmd = ["railway", "variables", "--set", f"{key}={secret_value}"]
        masked_cmd = ["railway", "variables", "--set", f"{key}=<HIDDEN:{receipt['fingerprint']}>"]
        if service:
            cmd.extend(["--service", service])
            masked_cmd.extend(["--service", service])
        if environment:
            cmd.extend(["--environment", environment])
            masked_cmd.extend(["--environment", environment])
    elif provider == "vercel":
        env_target = environment or "production"
        cmd = ["vercel", "env", "add", key, env_target]
        masked_cmd = ["vercel", "env", "add", key, env_target]
    else:
        raise ValueError(f"Unsupported provider: {provider}")

    if dry_run:
        return {
            "status": "DRY_RUN_READY",
            "provider": provider,
            "project": project,
            "service": service,
            "key": key,
            "masked_command": " ".join(masked_cmd),
            "receipt": receipt,
        }

    proc = subprocess.run(
        cmd,
        input=secret_value if provider == "vercel" else None,
        capture_output=True,
        text=True,
        check=False,
    )

    return {
        "status": "INJECTED" if proc.returncode == 0 else "CLI_ERROR",
        "exit_code": proc.returncode,
        "provider": provider,
        "project": project,
        "service": service,
        "key": key,
        "masked_command": " ".join(masked_cmd),
        "receipt": receipt,
        "stderr": proc.stderr.strip() if proc.returncode != 0 else "",
    }
