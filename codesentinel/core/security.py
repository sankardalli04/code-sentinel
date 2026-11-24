import hmac
import hashlib
from codesentinel.core.logger import logger


def verify_github_signature(payload_body: bytes, secret: str, signature_header: str | None) -> bool:
    """
    Verifies that the webhook payload was sent from GitHub using HMAC-SHA256.

    Args:
        payload_body: Raw bytes of the HTTP request body.
        secret: Webhook secret configured in GitHub repository.
        signature_header: Value of the 'X-Hub-Signature-256' header.

    Returns:
        True if the signature is valid, False otherwise.
    """
    if not signature_header:
        logger.warning("Missing X-Hub-Signature-256 header")
        return False

    if not signature_header.startswith("sha256="):
        logger.warning("Invalid signature header format; must start with 'sha256='")
        return False

    expected_signature = hmac.new(
        key=secret.encode("utf-8"),
        msg=payload_body,
        digestmod=hashlib.sha256
    ).hexdigest()

    received_signature = signature_header.split("sha256=")[1]
    is_valid = hmac.compare_digest(expected_signature, received_signature)

    if not is_valid:
        logger.warning("GitHub webhook signature mismatch")
    return is_valid
