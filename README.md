# Surface Python SDK

Python client for the [Surface](https://tendrl.com/products/surface) file scanning API. Supports two modes: **API mode** (remote scanning via the Surface API) and **Local mode** (scanning via a local scanner daemon). Uses HTTP/2 by default.

## Installation

```bash
uv pip install "git+https://github.com/tendrl-inc-labs/surface-python"

# or with pip
pip install "git+https://github.com/tendrl-inc-labs/surface-python"
```

## Scan Modes

| Mode | Description | API Key Required | Network Required |
|------|-------------|-----------------|-----------------|
| **API** (default) | Sends files to the Surface API | Yes | Yes |
| **Local** | Sends files to a local scanner daemon | Yes | No |

## Quick Start — API Mode

The shortest integration is the `@scan` decorator: hand it a file, your function receives the `ScanResult`, and files matching `reject` never reach it.

```python
from surface import ScanResult, scan

@scan(reject=["Block"])   # refuse what the scanner recommends blocking
def process(result: ScanResult):
    print(result.safety_score.threat_level)  # Clean, Suspicious, or Malicious
    # ... your logic runs only for accepted files

process("suspicious.exe")   # you pass the file; process() gets the result
```

`reject` matches the recommended action (`"Block"`, `"Review"`) or the threat level (`"Malicious"`, `"Suspicious"`) — a rejected file raises `MaliciousFileError` before your function runs.

Prefer to hold the client yourself? The same scan is one method call:

```python
from surface import SurfaceClient

# Uses SURFACE_KEY env var automatically
client = SurfaceClient()

# Or pass explicitly
client = SurfaceClient("sfk_your_token_here")

# Scan a file
result = client.scan_file("suspicious.exe")
print(result.safety_score.threat_level)  # Clean, Suspicious, or Malicious
print(result.safety_score.score)          # 0-100 safety score

# Context manager
with SurfaceClient() as client:
    result = client.scan_file("document.pdf")
```

## Quick Start — Local Mode

Requires the scanner daemon running on localhost (e.g. `surface-scanner --daemon --listen=:8090`).

```python
from surface import SurfaceClient

client = SurfaceClient(mode="local", scanner_url="http://127.0.0.1:8090")
result = client.scan_file("suspicious.exe")
print(result.safety_score.threat_level)
```

The same `scan_file`, `get_scan`, and deferred scanning methods work in both modes.

## Authentication

The client checks for an API key in this order:

1. `api_key` parameter passed to `SurfaceClient()`
2. `SURFACE_KEY` environment variable

```bash
export SURFACE_KEY="sfk_your_token_here"
```

If neither is set, an `AuthenticationError` is raised at construction time.

## Scanning Files

`scan_file` accepts a file path, bytes, or file-like object:

```python
# From path, bytes, or file-like
result = client.scan_file("malware.exe")
result = client.scan_file(file_bytes)
result = client.scan_file(open("sample.zip", "rb"))

# Reject malicious files — raises MaliciousFileError
result = client.scan_file("upload.exe", reject="malicious")
result = client.scan_file("upload.exe", reject=["malicious", "suspicious"])

# Deferred scan (returns immediately, poll for results)
deferred = client.scan_file("large_archive.zip", defer_scan=True)
scan = client.get_scan(deferred.scan_id)
```

## Scan Payload

Scan raw content without writing to disk. Accepts `str` or `bytes` and an optional filename label:

```python
# Sync — string payload sent as raw text
result = client.scan_payload("<?php system('id');", "test.php")

# Async
async with AsyncSurfaceClient() as client:
    result = await client.scan_payload("<?php system('id');", "test.php")
```

String payloads are sent as raw text to `POST /api/scan/payload` (max 10 MB). Binary `bytes` payloads are automatically base64-encoded by the SDK. Auth, billing, and response format are identical to `scan_file`.

## Agentic Security

Payload scan results may include additional threat detection from agentic security engines. These fields are present on `ScanResult` as `dict | None`:

- **`code_extraction`** — embedded code blocks found in the payload (scripts, shell commands)
- **`prompt_injection`** — prompt injection attempts detected in text content
- **`sensitive_data`** — exposed credentials, API keys, or PII
- **`tool_call_analysis`** — suspicious tool/function call patterns

```python
if result.prompt_injection and result.prompt_injection.get("detected"):
    print("Prompt injection detected in payload")
```

## `@scan` Decorator

Wraps a function so the caller passes a file and the function receives a `ScanResult`:

```python
from surface import scan, ScanResult

@scan
def process(result: ScanResult):
    print(result.safety_score.threat_level)

process("suspect.exe")  # pass file path, bytes, or file-like

# With filtering — raises MaliciousFileError on reject
@scan(reject=["malicious", "suspicious"])
def process(result: ScanResult):
    ...

# Local scanner + filtering
@scan(reject="malicious", mode="local")
def process(result: ScanResult):
    ...
```

The client is lazily created on first call and cached across invocations.

## Middleware

The `@scan_request` decorator scans incoming request bodies on individual routes:

```python
from surface.middleware import scan_request

@app.post("/ingest")
@scan_request(client, reject=["Malicious"])
async def ingest(request: Request):
    body = await request.body()
    return {"status": "ok"}
```

For application-wide scanning, use the ASGI middleware with FastAPI or Starlette:

```python
from surface.middleware import ScanMiddleware

app.add_middleware(ScanMiddleware, client=client, reject=["Malicious"], fail_open=True)
```

Flask sync routes are also supported via the same `@scan_request` decorator. Options: `reject`, `label`, `fail_open`, `min_size`, `paths`, `on_threat`, `on_error`.

## Account & Usage

```python
# Scan usage for the current billing period
usage = client.get_usage()
print(f"{usage.scans_used}/{usage.max_scans} scans used this period ({usage.scans_remaining} remaining)")

# Account details
account = client.get_account()
```

## Scan Profiles

```python
profiles = client.list_profiles()

profile = client.create_profile(
    name="Images Only",
    allowed_types="jpg,jpeg,png,gif,webp",
    max_file_size=10485760,
)

client.update_profile(profile.id, name="Images & PDFs", allowed_types="jpg,jpeg,png,gif,webp,pdf")
client.delete_profile(profile.id)
```

### Profile Engine Configuration

Control which engines run and configure per-engine settings via `engine_config`:

```python
profile = client.create_profile(
    name="Agentic Intake",
    allowed_types="json,txt,md",
    enable_payload_scan=True,
    engine_config={
        "prompt_injection": {"enabled": True},
        "sensitive_data": {"enabled": True, "mask_output": True},
        "ml": {"threshold": 0.8},
    },
)
```

New accounts automatically get three built-in profiles: **Default** (common file types, all engines), **All File Types** (all types, all engines), and **Agentic** (all types, strict sensitive data detection, auto IP blocking — optimized for agent-to-agent middleware).

## API Keys

```python
keys = client.list_api_keys()
new_key = client.create_api_key("Production", profile_id=profile.id)
client.delete_api_key(key_id)
```

## Scan History

```python
history = client.get_scan_history(page=1, limit=25)
for scan in history.scans:
    print(f"{scan.filename}: {scan.threat_level} (history credits_used={scan.credits_used})")
```

## Webhook Verification

```python
from surface import verify_webhook_signature

is_valid = verify_webhook_signature(
    body=request.body,
    secret="your_webhook_secret",
    signature_header=request.headers["X-Surface-Signature"],
)
```

## Async Client

`AsyncSurfaceClient` provides the same API with `async`/`await` support, built on `httpx.AsyncClient`:

```python
import asyncio
from surface import AsyncSurfaceClient

async def main():
    async with AsyncSurfaceClient() as client:
        result = await client.scan_file("suspicious.exe")
        print(result.safety_score.threat_level)

asyncio.run(main())
```

### Batch Scanning

Scan multiple files concurrently with `scan_files()`. Concurrency is controlled by `max_concurrency` (default 10):

```python
async with AsyncSurfaceClient(max_concurrency=5) as client:
    results = await client.scan_files([
        "file1.exe",
        "file2.pdf",
        "file3.zip",
        Path("/uploads/doc.docx"),
    ])
    for result in results:
        print(f"{result.name}: {result.safety_score.threat_level}")
```

### FastAPI Integration

```python
from fastapi import FastAPI, UploadFile, HTTPException
from surface import AsyncSurfaceClient, MaliciousFileError

app = FastAPI()
client = AsyncSurfaceClient()

@app.post("/upload")
async def upload(file: UploadFile):
    content = await file.read()
    try:
        result = await client.scan_file(content, reject="malicious")
    except MaliciousFileError as e:
        raise HTTPException(400, f"File rejected: {e.result.safety_score.threat_level}")
    return {"status": "clean", "score": result.safety_score.score}
```

## Error Handling

```python
from surface import (
    SurfaceError,
    AuthenticationError,
    QuotaExceededError,
    RateLimitError,
    NotFoundError,
    ValidationError,
)

try:
    result = client.scan_file("test.exe")
except QuotaExceededError:
    print("Monthly scan quota exhausted")
except RateLimitError:
    print("Rate limit hit, slow down")
except AuthenticationError:
    print("Invalid API key")
except SurfaceError as e:
    print(f"API error {e.status_code}: {e.message}")
```

## Requirements

- Python 3.9+
- `httpx[http2]`, `pydantic` v2
