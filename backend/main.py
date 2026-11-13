
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from backend.qr_module.decoder import decode_qr_image
from backend.qr_module.analyzer import analyze_qr_content


app = FastAPI(
    title="TrustCheck QR Security API",
    description="QR decoding, content interpretation and scam risk analysis",
    version="1.3.0"
)

# CORS configuration
# Restrict allowed origins before production deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)

MAX_FILE_SIZE = 5 * 1024 * 1024

URL_QR_TYPES = {
    "URL",
    "PAYMENT_URL",
    "WHATSAPP_GROUP",
    "WHATSAPP_CHAT"
}

# Sensitive credentials and authentication data
SENSITIVE_KEYS = {
    "password",
    "passwd",
    "psk",
    "passphrase",
    "secret",
    "token",
    "otp",
    "credential",
    "authorization",
    "auth_key",
    "api_key",
    "access_key",
    "session",
    "query_parameters"
}

# Personal or private information
PRIVATE_KEYS = {
    "name",
    "full_name",
    "organisation",
    "organization",
    "phone",
    "phone_number",
    "phone_numbers",
    "mobile",
    "email",
    "emails",
    "address",
    "addresses",
    "notes",
    "message",
    "prefilled_message",
    "recipient",
    "recipient_number",
    "upi_id",
    "payee_name",
    "wallet_address",
    "payment_parameters"
}


def should_hide_value(key):
    """
    Determine whether a field contains sensitive or private information.
    """

    key = str(key).lower()

    # Preserve boolean indicators such as recipient_present.
    if key.endswith("_present"):
        return False

    if key in SENSITIVE_KEYS or key in PRIVATE_KEYS:
        return True

    if any(secret in key for secret in SENSITIVE_KEYS):
        return True

    return False


def sanitize_details(value, parent_key=""):
    """
    Recursively hide sensitive credentials and personal information.
    """

    if should_hide_value(parent_key):
        return "[Hidden for privacy and security]"

    if isinstance(value, dict):
        sanitized = {}

        for child_key, child_value in value.items():
            sanitized[child_key] = sanitize_details(
                child_value,
                str(child_key)
            )

        return sanitized

    if isinstance(value, list):
        return [
            sanitize_details(item, parent_key)
            for item in value
        ]

    return value


def prepare_safe_result(analysis):
    """
    Prepare a privacy-conscious API response.
    """

    result = dict(analysis)

    # Never return the original QR payload.
    result["raw_content"] = "[Hidden for privacy]"

    # Sanitize all extracted QR details.
    result["details"] = sanitize_details(
        result.get("details", {})
    )

    return result


def get_external_check_status(qr_type):
    """
    Safe Browsing is currently disabled.

    URL QR codes need a NOT_CHECKED status.
    Non-URL QR codes do not require URL threat checking.
    """

    if qr_type in URL_QR_TYPES:
        return {
            "status": "NOT_CHECKED",
            "message": (
                "External URL threat checking is currently disabled. "
                "The URL has not been verified against threat intelligence."
            )
        }

    return {
        "status": "NOT_APPLICABLE",
        "message": (
            "External URL threat checking is not applicable "
            "to this QR code type."
        )
    }


@app.get("/")
def home():
    return {
        "success": True,
        "project": "TrustCheck",
        "module": "QR Scam Detection",
        "message": "QR Security API is running",
        "version": "1.3.0"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "module": "QR Scam Detection",
        "ai_analysis": "Gemini integration configured"
    }


@app.post("/scan")
async def scan_qr(
    file: UploadFile = File(...),
    language: str = Query(
        default="English",
        min_length=2,
        max_length=30,
        description="Language for the AI-generated explanation"
    )
):

    # 1. Validate uploaded image format
    allowed_types = {
        "image/png",
        "image/jpeg",
        "image/webp"
    }

    content_type = (file.content_type or "").lower().strip()

    if content_type not in allowed_types:
        await file.close()

        raise HTTPException(
            status_code=400,
            detail="Only PNG, JPG, JPEG and WEBP images are supported."
        )

    # 2. Read uploaded image with size limit
    try:
        image_bytes = await file.read(MAX_FILE_SIZE + 1)

    finally:
        await file.close()

    if not image_bytes:
        raise HTTPException(
            status_code=400,
            detail="Uploaded image is empty."
        )

    if len(image_bytes) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="Image exceeds the 5 MB upload limit."
        )

    # 3. Decode QR codes
    try:
        decoded = decode_qr_image(image_bytes)

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while decoding the QR image."
        )

    if not isinstance(decoded, dict):
        raise HTTPException(
            status_code=500,
            detail="The QR decoder returned an invalid response."
        )

    if not decoded.get("success"):
        return {
            "success": False,
            "message": decoded.get(
                "message",
                "No QR code found."
            ),
            "total_qr_codes": 0,
            "results": []
        }

    decoded_results = decoded.get("results", [])

    if not isinstance(decoded_results, list):
        decoded_results = []

    analyzed_results = []

    # 4. Analyze each decoded QR code
    for content in decoded_results:

        if not isinstance(content, str) or not content.strip():
            continue

        try:
            # Classification and parsing happen inside the analyzer.
            # No duplicate classification is required.
            analysis = analyze_qr_content(
                content,
                external_check=None,
                language=language
            )

            qr_type = analysis.get("qr_type", "UNKNOWN")

            # Prepare privacy-conscious response
            safe_result = prepare_safe_result(analysis)

            # Add accurate external-check status
            external_status = get_external_check_status(qr_type)

            safe_result["external_security_check"] = external_status

            analyzed_results.append(safe_result)

        except Exception:
            # Never expose raw QR content or internal error details.
            analyzed_results.append({
                "success": False,
                "message": "This QR code could not be analysed.",
                "qr_type": "UNKNOWN",
                "raw_content": "[Hidden for privacy]",
                "details": {},
                "security_status": "NOT_CHECKED",
                "external_security_check": {
                    "status": "NOT_CHECKED",
                    "message": "The QR code could not be fully analysed."
                },
                "risk_analysis": {
                    "risk_level": "INCONCLUSIVE",
                    "risk_score": 0,
                    "score_is_probability": False,
                    "assessment_status": "ANALYSIS_FAILED",
                    "findings": [],
                    "recommendation": (
                        "The QR analysis failed. Do not proceed "
                        "until its contents have been verified."
                    )
                },
                "ai_analysis": {
                    "status": "UNAVAILABLE",
                    "message": "AI analysis could not be completed."
                }
            })

    # 5. Return final results
    return {
        "success": True,
        "message": "QR code analysis completed successfully.",
        "total_qr_codes": len(analyzed_results),
        "language": language,
        "results": analyzed_results
    }
