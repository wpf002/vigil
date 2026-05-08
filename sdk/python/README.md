# VIGIL Python SDK

Lightweight, dataclass-only client for the VIGIL public API.

## Install

```bash
pip install vigil-sdk
```

## Authentication

Generate an API key from the VIGIL console (Settings → API Keys). The key
is shown exactly once — store it in your secrets manager. Keys carry
scopes; pick the minimum your integration needs.

## Quickstart

```python
from vigil_sdk import VIGILClient

client = VIGILClient(api_key="vgl_...", base_url="https://vigil.example.com")

# List active attacks above a confidence threshold.
for a in client.list_attacks(min_confidence=0.7, limit=20):
    print(a.attack_id, a.current_phase, a.confidence)

# Pull executive summary.
summary = client.get_executive_summary()
print("MTTR (7d):", summary.mttr_seconds_7d)

# Submit a normalized CDM event from your own pipeline.
client.submit_signal({
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "source_event_id": "abc-123",
    "source_siem": "custom",
    "title": "Suspicious sign-in",
    "severity": "high",
    "timestamp": "2026-05-08T01:00:00Z",
    "raw_event": {},
})
```

## Client methods

- `list_attacks(phase=None, min_confidence=None, limit=50)` → `list[AttackState]`
- `get_attack(attack_id)` → `AttackState`
- `list_detections(tactic=None, limit=100)` → `list[DetectionVersion]`
- `get_coverage()` → `dict`
- `get_executive_summary()` → `ExecutiveSummary`
- `submit_signal(cdm_event_dict)` → `dict`
- `list_playbooks(limit=50)` → `list[PlaybookRun]`

## Webhook verification

```python
from vigil_sdk import verify_webhook_signature

@app.post("/vigil/hook")
async def handle(request):
    body = await request.body()
    sig = request.headers.get("X-VIGIL-Signature", "")
    if not verify_webhook_signature(body, sig, secret=os.environ["VIGIL_WEBHOOK_SECRET"]):
        return Response(status_code=401)
    payload = json.loads(body)
    # ... handle payload["event"], payload["data"] ...
```

## Errors

- `VIGILAuthError` — 401/403 (bad or revoked key, missing scope)
- `VIGILNotFoundError` — 404
- `VIGILRateLimitError` — 429
- `VIGILAPIError` — base class for every other failure
