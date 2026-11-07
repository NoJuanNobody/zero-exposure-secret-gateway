---
name: zero-exposure-secret-gateway
description: Conversational wrapper and zero-exposure terminal secret injector for Railway, Vercel, and cloud secret managers. Resolves environment variable keys from natural language descriptions and collects secret values via hidden local console input (getpass) so API keys never enter LLM chat trajectories or model logs.
---

# Zero-Exposure Secret Gateway (`zero-exposure-secret-gateway`)

A conversational CLI wrapper and agent skill that eliminates the security vulnerability of pasting API keys into LLM chat trajectories. You describe what you are trying to do and which hosted app/tool needs a secret; the gateway resolves the canonical environment variable key(s), collects the secret locally via hidden terminal input (`getpass`), and injects it directly into **Railway** (or Vercel, Fly.io, `.env.local`) via `subprocess`—returning only a non-reversible SHA-256 fingerprint to the chat session.

---

## When to Use This Skill

1. **Injecting Secrets into Railway / Cloud Projects**: When setting API keys, database URLs, or webhook secrets on Railway (`railway variables --set`) without pasting the raw key into Claude Code, Antigravity, or Gemini chat windows.
2. **Conversational Variable Resolution**: When the user describes the integration in plain English (e.g., *"I need to add my OpenAI key and Twilio token to the railway-comms service"*) and wants an interactive terminal prompt to paste the secret securely.
3. **Trajectory Leak Prevention**: Scanning prompts or logs to redact accidentally pasted secrets (`sk-...`, `ghp_...`, `xoxb-...`, `rk_live_...`) before they persist in transcripts.

---

## Quick Start & CLI Usage

### 1. Conversational Secret Resolution & Hidden Terminal Injection (`inject`)

```bash
# Interactive mode: explain what you're doing, then paste the secret (hidden input)
python3 -m zero_exposure_secret_gateway.cli inject \
  --project "railway-comms" \
  --service "api-gateway" \
  --describe "I need to configure the OpenAI API key for our voice agent"
```

Or specify `--key` directly (with `--dry-run` to preview the exact Railway CLI invocation without executing):

```bash
python3 -m zero_exposure_secret_gateway.cli inject \
  --project "identity-sentinel" \
  --key "OPENAI_API_KEY" \
  --provider railway \
  --dry-run
```

### 2. Resolve Natural Language to Canonical Environment Keys (`resolve`)

```bash
python3 -m zero_exposure_secret_gateway.cli resolve \
  --describe "Connecting Stripe billing and Supabase service role to our Railway backend"
```

### 3. Scan & Redact Chat Trajectories (`scan`)

```bash
python3 -m zero_exposure_secret_gateway.cli scan \
  --text "Here is my key sk-proj-1234567890abcdef1234567890abcdef for Railway"
```

---

## Security Architecture

```
[ User Natural Language Intent ]
       │  ("Set up OpenAI key on railway-comms")
       ▼
[ Conversational Intent Resolver ] ──► Resolves: project="railway-comms", key="OPENAI_API_KEY"
       │
       ▼
[ Local Hidden Terminal Prompt (getpass) ] ◄── User pastes secret locally (zero echo, zero chat log)
       │
       ├──► [ Subprocess: railway variables --set OPENAI_API_KEY=<hidden> ] ──► Railway Cloud Secret Store
       │
       └──► [ Truncated SHA-256 Receipt: sha256:a4f91c82 ] ──► Returned safely to Coding Agent
```
