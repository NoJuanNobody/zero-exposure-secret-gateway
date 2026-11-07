# zero-exposure-secret-gateway

Conversational wrapper and zero-exposure terminal secret injector for Railway and cloud secret managers. Ensures API keys never touch LLM chat trajectories, transcripts, or model servers.

## Features

- **Conversational Intent Resolver**: Maps natural language descriptions of tools/services to canonical environment variable names (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `STRIPE_SECRET_KEY`, `CLERK_SECRET_KEY`, `TWILIO_AUTH_TOKEN`, `SUPABASE_SERVICE_ROLE_KEY`, `DATABASE_URL`, etc.).
- **Zero-Exposure Hidden Input (`getpass`)**: Collects secrets directly in the local terminal with echo disabled and injects them via `railway variables --set` (`subprocess.run` without shell interpolation).
- **Cryptographic Verification Receipt**: Emits a truncated SHA-256 fingerprint (`sha256:xxxxxxxx`) so coding agents can verify a secret was set without ever seeing the secret value.
- **Trajectory Secret Scanner & Redactor**: Detects and scrubs accidentally pasted tokens from chat logs.

## Installation

```bash
pip install -e .
```

## Verification

```bash
python3 -m unittest discover -v -s tests
```
