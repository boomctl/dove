"""dove access gate — the full tier's policy enforcer and page server.

Fronted by a Lambda Function URL. Three routes:

  GET /d/<id>/<name>  → serve the decryptor page (no decrement; unfurler-safe)
  GET /meta/<id>      → the share's policy as JSON (free; for the page to show
                        expiry / downloads-left and decide small-vs-large)
  GET /dl/<id>        → check + atomically decrement the download budget, then
                        302 to a short-lived presigned S3 URL

It never sees the decryption key — that rides the URL fragment, which browsers
and HTTP clients never send. Environment: BUCKET, TABLE.
"""

import base64
import hashlib
import json
import os
import time
from pathlib import Path

import boto3

BUCKET = os.environ["BUCKET"]
TABLE = os.environ["TABLE"]

# Wrong-PIN guesses allowed before the share locks. Small, because the gate
# checks online — a handful of tries against a 6-digit PIN is negligible odds,
# and locking makes brute force impossible rather than merely slow.
MAX_PIN_ATTEMPTS = 5

_ddb = boto3.client("dynamodb")
_s3 = boto3.client("s3")
PAGE = (Path(__file__).parent / "share.html").read_text()
# The link-preview image messaging apps show when a share link is pasted. Generic
# and branded — it can't reveal the filename (that's E2E), which is the point.
OG_PNG = (Path(__file__).parent / "og.png").read_bytes()


def _resp(status, body="", content_type="text/plain; charset=utf-8", extra=None):
    headers = {"content-type": content_type}
    if extra:
        headers.update(extra)
    return {"statusCode": status, "headers": headers, "body": body}


def _origin(event):
    """This gate's own reachable origin, for absolute og:image / og:url."""
    dom = event.get("requestContext", {}).get("domainName", "")
    return f"https://{dom}" if dom else ""


def handler(event, _context):
    raw = event.get("rawPath", "")
    if raw == "/og.png":
        # Binary link-preview image (unfurlers fetch this via og:image).
        return {
            "statusCode": 200,
            "headers": {"content-type": "image/png", "cache-control": "public, max-age=86400"},
            "body": base64.b64encode(OG_PNG).decode(),
            "isBase64Encoded": True,
        }
    parts = [p for p in raw.split("/") if p]
    if len(parts) < 2:
        return _resp(404, "not a dove share link")
    route, share_id = parts[0], parts[1]

    if route == "d":
        # The decryptor page. No decrement — opening a link (or an unfurler
        # previewing it) never spends a download. Inject this gate's origin so the
        # og:image / og:url are absolute (unfurlers require it).
        page = PAGE.replace("__OGBASE__", _origin(event))
        return _resp(200, page, "text/html; charset=utf-8")

    if route == "meta":
        return _meta(share_id)

    if route == "verify":
        # PIN pre-check for the browser's two-step flow: verify + rate-limit
        # WITHOUT spending a download. The download happens on the explicit click.
        params = event.get("queryStringParameters") or {}
        return _verify(share_id, params.get("pin"))

    if route == "dl":
        params = event.get("queryStringParameters") or {}
        return _download(share_id, params.get("pin"))

    return _resp(404, "not a dove share link")


def _meta(share_id):
    item = _ddb.get_item(TableName=TABLE, Key={"id": {"S": share_id}}).get("Item")
    if not item:
        return _resp(404, json.dumps({"error": "not found"}), "application/json")
    # Size is stored on the item (no per-request HeadObject). The filename is NOT
    # here — it's end-to-end encrypted in the link's fragment, which the gate
    # never sees. The page decrypts it client-side.
    size = int(item.get("size", {}).get("N", "0"))
    if not size:  # older shares written before size was stored
        try:
            size = _s3.head_object(Bucket=BUCKET, Key=item["s3_key"]["S"])["ContentLength"]
        except Exception:  # noqa: BLE001
            pass
    pin_required = "pin_hash" in item
    locked = pin_required and int(item.get("pin_attempts", {}).get("N", "0")) >= MAX_PIN_ATTEMPTS
    body = json.dumps(
        {
            "downloads_remaining": int(item["downloads_remaining"]["N"]),
            "downloads_total": int(item.get("downloads_total", {}).get("N", "0")),
            "expires_at": int(item["expires_at"]["N"]),
            "size": size,
            # Opaque encrypted blob (filename + trust); the client decrypts it with
            # the fragment secret. The gate can't read it.
            "meta": item.get("meta", {}).get("S", ""),
            "pin_required": pin_required,
            "locked": locked,
        }
    )
    return _resp(200, body, "application/json", {"access-control-allow-origin": "*"})


def _pin_gate(share_id, item, pin):
    """Verify a PIN-locked share. Returns an error response to send back, or None
    to allow the download. A wrong guess is counted; enough of them lock it."""
    pin_hash = item.get("pin_hash", {}).get("S")
    if not pin_hash:
        return None  # not PIN-locked
    attempts = int(item.get("pin_attempts", {}).get("N", "0"))
    if attempts >= MAX_PIN_ATTEMPTS:
        return _resp(423, json.dumps({"error": "locked"}), "application/json")
    if not pin:
        return _resp(401, json.dumps({"error": "pin required"}), "application/json")
    if hashlib.sha256(f"{share_id}:{pin}".encode()).hexdigest() == pin_hash:
        return None  # correct — allow through
    # Wrong. Count it atomically; the same op locks the share at the ceiling.
    try:
        res = _ddb.update_item(
            TableName=TABLE,
            Key={"id": {"S": share_id}},
            UpdateExpression="SET pin_attempts = if_not_exists(pin_attempts, :z) + :one",
            ConditionExpression="attribute_not_exists(pin_attempts) OR pin_attempts < :max",
            ExpressionAttributeValues={
                ":one": {"N": "1"},
                ":z": {"N": "0"},
                ":max": {"N": str(MAX_PIN_ATTEMPTS)},
            },
            ReturnValues="ALL_NEW",
        )
        remaining = max(0, MAX_PIN_ATTEMPTS - int(res["Attributes"]["pin_attempts"]["N"]))
    except _ddb.exceptions.ConditionalCheckFailedException:
        return _resp(423, json.dumps({"error": "locked"}), "application/json")
    status = 423 if remaining == 0 else 401
    error = "locked" if remaining == 0 else "wrong pin"
    return _resp(
        status,
        json.dumps({"error": error, "attempts_remaining": remaining}),
        "application/json",
    )


def _verify(share_id, pin):
    now = int(time.time())
    item = _ddb.get_item(TableName=TABLE, Key={"id": {"S": share_id}}).get("Item")
    if not item or int(item["expires_at"]["N"]) <= now or int(item["downloads_remaining"]["N"]) <= 0:
        return _resp(410, json.dumps({"error": "gone"}), "application/json")
    # Same PIN gate as the download (verify + rate-limit + lock), but no decrement.
    gate = _pin_gate(share_id, item, pin)
    if gate is not None:
        return gate
    return _resp(200, json.dumps({"ok": True}), "application/json")


def _download(share_id, pin):
    now = int(time.time())
    item = _ddb.get_item(TableName=TABLE, Key={"id": {"S": share_id}}).get("Item")
    if not item:
        return _resp(410, "this share has expired or reached its download limit")
    if int(item["expires_at"]["N"]) <= now or int(item["downloads_remaining"]["N"]) <= 0:
        return _resp(410, "this share has expired or reached its download limit")

    # Second factor: verify the PIN (if any) before spending a download.
    gate = _pin_gate(share_id, item, pin)
    if gate is not None:
        return gate

    try:
        # Atomic: decrement only if the share exists, has budget, and is unexpired.
        result = _ddb.update_item(
            TableName=TABLE,
            Key={"id": {"S": share_id}},
            UpdateExpression="SET downloads_remaining = downloads_remaining - :one",
            ConditionExpression=(
                "attribute_exists(id) "
                "AND downloads_remaining > :zero "
                "AND expires_at > :now"
            ),
            ExpressionAttributeValues={
                ":one": {"N": "1"},
                ":zero": {"N": "0"},
                ":now": {"N": str(now)},
            },
            ReturnValues="ALL_NEW",
        )
    except _ddb.exceptions.ConditionalCheckFailedException:
        return _resp(410, "this share has expired or reached its download limit")
    except Exception:  # noqa: BLE001 - never leak internals to a downloader
        return _resp(500, "the gate hit an error")

    s3_key = result["Attributes"]["s3_key"]["S"]
    # The presign window governs when the download must *start* (and leaves room
    # to resume a dropped transfer) — NOT how long it may run. S3 checks expiry
    # at request time; once the GET is accepted it streams the whole object even
    # if the window passes, so huge multi-hour downloads are fine as long as they
    # begin within the window (clients follow the 302 immediately). 15 minutes
    # gives resume headroom, well within the Lambda role's credential lifetime.
    presigned = _s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": BUCKET, "Key": s3_key},
        ExpiresIn=900,
    )
    return _resp(302, "", extra={"location": presigned})
