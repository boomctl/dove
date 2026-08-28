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

import json
import os
import time
from pathlib import Path

import boto3

BUCKET = os.environ["BUCKET"]
TABLE = os.environ["TABLE"]

_ddb = boto3.client("dynamodb")
_s3 = boto3.client("s3")
PAGE = (Path(__file__).parent / "share.html").read_text()


def _resp(status, body="", content_type="text/plain; charset=utf-8", extra=None):
    headers = {"content-type": content_type}
    if extra:
        headers.update(extra)
    return {"statusCode": status, "headers": headers, "body": body}


def handler(event, _context):
    parts = [p for p in event.get("rawPath", "").split("/") if p]
    if len(parts) < 2:
        return _resp(404, "not a dove share link")
    route, share_id = parts[0], parts[1]

    if route == "d":
        # The decryptor page. No decrement — opening a link (or an unfurler
        # previewing it) never spends a download.
        return _resp(200, PAGE, "text/html; charset=utf-8")

    if route == "meta":
        return _meta(share_id)

    if route == "dl":
        return _download(share_id)

    return _resp(404, "not a dove share link")


def _meta(share_id):
    item = _ddb.get_item(TableName=TABLE, Key={"id": {"S": share_id}}).get("Item")
    if not item:
        return _resp(404, json.dumps({"error": "not found"}), "application/json")
    s3_key = item["s3_key"]["S"]
    size = 0
    try:
        size = _s3.head_object(Bucket=BUCKET, Key=s3_key)["ContentLength"]
    except Exception:  # noqa: BLE001
        pass
    body = json.dumps(
        {
            "downloads_remaining": int(item["downloads_remaining"]["N"]),
            "expires_at": int(item["expires_at"]["N"]),
            "size": size,
            "name": s3_key.split("/", 1)[-1],
        }
    )
    return _resp(200, body, "application/json", {"access-control-allow-origin": "*"})


def _download(share_id):
    now = int(time.time())
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
