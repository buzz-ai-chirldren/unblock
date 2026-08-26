"""Shared Strands model construction for the demo scripts.

Default provider is Bedrock (us-east-1) with credentials read from
BEDROCK_KEY_FILE, an IAM access-key JSON (console export or flat
AccessKeyId/SecretAccessKey). provider="anthropic" keeps the old path and
needs ANTHROPIC_API_KEY.
"""

from __future__ import annotations

import json
import os

BEDROCK_DEFAULT_MODEL = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"


def build_model(provider: str = "bedrock", model_id: str | None = None):
    if provider == "anthropic":
        from strands.models.anthropic import AnthropicModel

        return AnthropicModel(model_id=model_id or "claude-opus-5", max_tokens=4096)

    import boto3
    from strands.models import BedrockModel

    key_file = os.environ.get("BEDROCK_KEY_FILE")
    if not key_file:
        raise SystemExit(
            "BEDROCK_KEY_FILE is not set. Point it at an IAM access-key JSON "
            "with bedrock:InvokeModel permission."
        )
    creds = json.load(open(key_file))
    if "AccessKey" in creds:  # IAM console export wraps the key pair
        creds = creds["AccessKey"]
    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        region_name="us-east-1",
    )
    return BedrockModel(
        model_id=model_id or BEDROCK_DEFAULT_MODEL,
        boto_session=session,
        max_tokens=4096,
    )
