# NeuroGuard

**AI-native code security review powered by Gemma 4 Thinking Mode.**

[![PyPI version](https://img.shields.io/badge/pypi-v0.1.0-blue)](https://pypi.org/project/neuroguard/)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)
[![Gemma 4](https://img.shields.io/badge/Powered%20by-Gemma%204-orange)](https://ai.google.dev/gemma)

**[neuroguard-psi.vercel.app](https://neuroguard-psi.vercel.app)** · **[github.com/tyy130/neuroguard](https://github.com/tyy130/neuroguard)**

NeuroGuard reviews Python and JavaScript/TypeScript code for security vulnerabilities in real-time — streaming Gemma 4's full cognitive trace on the left while it produces a verified, secure rewrite on the right.

> Built for the [Dev.to Google Gemma 4 Challenge](https://dev.to/challenges/google-gemma-2026-05-06) · Python · JavaScript · TypeScript

---

## The Problem

[65% of AI-generated applications ship to production with critical security vulnerabilities](https://dev.to/devin-rosario/how-to-secure-vibe-coded-applications-in-2026-208d), mirroring classic OWASP Top 10 flaws. The most dangerous failure mode is the **hallucinated bypass**: an AI agent deletes authentication checks to resolve a compilation error — silently stripping the application of its security infrastructure.

The root cause is opacity. When a black-box model generates insecure code, you can't see _why_ it made that decision — and neither can the model.

## The Solution

Gemma 4's `<|think|>` token turns the model into a **glass box**. Every reasoning step is visible, auditable, and inspectable before the final output is accepted. NeuroGuard wires this directly into a security workflow:

1. Feed it a Python file or directory
2. Gemma 4 streams its full cognitive trace — you watch it find each vulnerability in real-time
3. It produces a complete, secure rewrite grounded in that explicit reasoning
4. [Bandit](https://bandit.readthedocs.io) independently verifies the rewrite is clean

---

## Demo

![NeuroGuard demo](demo/demo.gif)

The built-in demo file contains 5 intentional vulnerabilities:

- Hardcoded `SECRET_KEY` in source
- Unauthenticated admin routes (broken access control)
- SQL injection via f-string interpolation (×2)
- `eval()` on user input (remote code execution)
- Debug mode enabled in production

```
Before: 4 HIGH/MEDIUM Bandit findings
After:  ✓ CLEAN — Gemma 4's reasoning explains every fix
```

---

## Quickstart

```bash
pip install neuroguard
export GEMINI_API_KEY=your_key   # free at aistudio.google.com

neuroguard review app.py
```

---

## Installation

**Requirements:** Python 3.12+ · Free [Google AI Studio](https://aistudio.google.com) API key · Node.js (optional, for JS/TS projects)

```bash
pip install neuroguard
```

**Configure your API key** (one-time):

```bash
export GEMINI_API_KEY=your_api_key_here
```

Or add to a `.env` file in your project root:

```
GEMINI_API_KEY=your_api_key_here
```

---

## Usage

```bash
# Review a single Python file
neuroguard review app.py

# Review a JavaScript or TypeScript file
neuroguard review server.js
neuroguard review api.ts

# Review an entire directory (Python + JS/TS)
neuroguard review src/

# Save the secure rewrite
neuroguard review app.py --save app_secure.py

# JSON output (for CI/CD pipelines)
neuroguard review app.py --format json

# Use the MoE model (faster, slightly lower quality)
neuroguard review app.py --model gemma-4-26b-a4b-it

# Skip Bandit SAST verification
neuroguard review app.py --no-sast

# Add as a pre-commit hook
neuroguard install-hooks

# Version
neuroguard --version
```

**Exit codes:**

- `0` — file is clean (no HIGH/MEDIUM findings in original)
- `1` — vulnerabilities found in original code

This makes it CI/CD friendly: your pipeline fails if a file with known vulnerabilities is committed without review.

---

## CI/CD Integration

### GitHub Actions

Copy [`.github/workflows/neuroguard.yml`](.github/workflows/neuroguard.yml) into your repository. Add `GEMINI_API_KEY` to your repo secrets and NeuroGuard will run on every pull request that touches Python files.

### Pre-commit Hook

```bash
neuroguard install-hooks
pre-commit install
```

Or manually add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: neuroguard
        name: NeuroGuard Security Review
        entry: neuroguard review
        language: python
        types: [python]
        pass_filenames: true
        require_serial: true
```

---

## JSON Output

```bash
neuroguard review app.py --format json | jq '.original_findings'
```

Schema:

```json
{
  "file": "app.py",
  "model": "gemma-4-31b-it",
  "original_findings": 4,
  "rewrite_findings": [],
  "rewrite_valid_python": true,
  "thinking": "...",
  "response": "...",
  "secure_code": "..."
}
```

---

## Architecture

```
neuroguard/
├── cli.py             # Typer CLI — review, install-hooks, --version
├── agent.py           # Gemma 4 streaming client (google-genai SDK)
├── thinking_parser.py # Real-time <think>…</think> stream splitter
├── prompts.py         # Language-aware system prompt (activates Thinking Mode via <|think|>)
├── integrations.py    # Slack Block Kit, generic webhook, GitHub PR comments
├── tools/
│   ├── sast.py        # Bandit subprocess wrapper → Python findings
│   └── js_sast.py     # semgrep/regex SAST → JS/TS findings
└── ui.py              # Rich split-pane terminal layout
```

### How Thinking Mode Works

The system prompt begins with `<|think|>`, which activates Gemma 4's Thinking Mode. The Google AI Studio API delivers reasoning content as `thought=True` parts in the stream — separate from the final response.

`ThinkingStreamParser` wraps all thinking chunks in a single `<think>…</think>` span and routes content to the appropriate pane in real-time, handling tags that split across chunk boundaries.

### Models

| Model                | Type  | Active Params          | Notes                         |
| -------------------- | ----- | ---------------------- | ----------------------------- |
| `gemma-4-31b-it`     | Dense | 31B                    | Default — highest quality     |
| `gemma-4-26b-a4b-it` | MoE   | ~4B active / 26B total | Fallback — faster, lower cost |

Retries on 429/503 with exponential backoff and automatically falls back to the MoE model on persistent rate limits.

---

## What NeuroGuard Catches

| Vulnerability                     | OWASP | Python | JS/TS |
| --------------------------------- | ----- | ------ | ----- |
| SQL Injection                     | A03   | ✓      | ✓     |
| Hardcoded secrets                 | A02   | ✓      | ✓     |
| Missing authentication            | A01   | ✓      | ✓     |
| `eval()` / code injection         | A03   | ✓      | ✓     |
| Debug mode in production          | A05   | ✓      | ✓     |
| Insecure deserialization          | A08   | ✓      | —     |
| Weak cryptography / Math.random() | A02   | ✓      | ✓     |
| Path traversal                    | A01   | ✓      | ✓     |
| XSS (innerHTML / dangerouslySet)  | A03   | —      | ✓     |
| Command injection (exec)          | A03   | —      | ✓     |
| Prototype pollution               | A08   | —      | ✓     |

NeuroGuard is a **first-pass** tool. It does not replace a full penetration test or human security review. Runtime behavior, business logic flaws, and infrastructure misconfigurations are out of scope.

---

## Why Gemma 4

Standard LLMs are black boxes for security review — you see the output but not the reasoning. Gemma 4's Thinking Mode changes this:

- **Auditable**: inspect the exact reasoning path before accepting any rewrite
- **Trustworthy**: the model can't silently delete auth checks if its reasoning is visible
- **Compliance-ready**: regulated industries can log and audit AI decision-making
- **Open weight**: Apache 2.0 license — run it air-gapped, no data leaves your infrastructure

This is the shift from _vibe coding_ to _AI-native development_ — treating AI output as an untrusted first draft, verified by both visible reasoning and automated SAST.

---

## License

Apache 2.0 — same as Gemma 4 itself.
