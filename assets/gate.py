"""dove access gate — the full tier's policy enforcer.

Fronted by a Lambda Function URL. A recipient hits `/d/<id>/<name>`; this
checks and atomically decrements the share's download budget in DynamoDB, then
302-redirects to a short-lived presigned S3 URL so the ciphertext streams
straight from S3 (any size). It never sees the decryption key — that rides the
URL fragment, which browsers and HTTP clients never send.

Environment: BUCKET, TABLE. The Lambda role needs dynamodb:UpdateItem on the
table and s3:GetObject on the bucket (to sign the presigned URL).
"""

import os
import time

import boto3

BUCKET = os.environ["BUCKET"]
TABLE = os.environ["TABLE"]

_ddb = boto3.client("dynamodb")
_s3 = boto3.client("s3")


def _resp(status, body="", headers=None):
    h = {"content-type": "text/plain; charset=utf-8"}
    if headers:
        h.update(headers)
    return {"statusCode": status, "headers": h, "body": body}


def handler(event, _context):
    # Function URL path, e.g. "/d/<id>/<name>".
    parts = [p for p in event.get("rawPath", "").split("/") if p]
    if len(parts) < 2 or parts[0] != "d":
        return _resp(404, "not a dove share link")
    share_id = parts[1]

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
    # to resume a dropped transfer with a Range request) — NOT how long it may
    # run. S3 checks expiry at request time; once the GET is accepted it streams
    # the whole object even if the window passes, so huge multi-hour downloads
    # are fine as long as they begin within the window (clients follow the 302
    # immediately). 15 minutes gives generous resume headroom, well within the
    # Lambda role's credential lifetime (which itself caps the presign).
    presigned = _s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": BUCKET, "Key": s3_key},
        ExpiresIn=900,
    )
    return _resp(302, "", {"location": presigned})
