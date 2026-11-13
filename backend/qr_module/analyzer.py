
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from backend.qr_module.classifier import classify_qr_content
from backend.qr_module.parser import parse_qr_content
from backend.qr_module.risk_engine import analyze_qr_risk
from backend.qr_module.redirect_analyzer import inspect_redirects


# Gemini is optional. Local analysis must work without it.
try:
    from backend.qr_module.gemini_analyzer import analyze_with_gemini
except Exception as import_error:
    analyze_with_gemini = None
    print(
        "Gemini module unavailable:",
        repr(import_error),
        flush=True
    )


# ==========================================
# QR INFORMATION
# ==========================================

QR_INFORMATION = {
    "URL": {
        "description": "A website link encoded inside the QR code.",
        "purpose": "Scanning it may open a website or web application.",
        "action": "Check the actual website domain before opening the link."
    },
    "PAYMENT_URL": {
        "description": "A link that appears to be associated with an online payment.",
        "purpose": "It may open a payment page or payment provider.",
        "action": "Verify the merchant and payment amount before proceeding."
    },
    "UPI_PAYMENT": {
        "description": "A UPI payment request containing payment-related information.",
        "purpose": "A UPI application may use this information to prepare a payment.",
        "action": "Verify the recipient name and amount in your UPI application."
    },
    "UPI": {
        "description": "A UPI-related payment URI.",
        "purpose": "It may open a UPI application or prepare a payment.",
        "action": "Check the recipient and transaction details before authorising payment."
    },
    "UPI_ID": {
        "description": "A UPI payment address.",
        "purpose": "It identifies a payment destination, but does not prove who owns the account.",
        "action": "Verify the displayed recipient name in your payment application."
    },
    "WHATSAPP_GROUP": {
        "description": "A WhatsApp group invitation link.",
        "purpose": "It may open an invitation to join a WhatsApp group.",
        "action": "Verify the group and its source before joining."
    },
    "WHATSAPP_CHAT": {
        "description": "A WhatsApp chat or message link.",
        "purpose": "It may open a conversation with a WhatsApp account.",
        "action": "Verify the contact before sharing personal or financial information."
    },
    "WIFI": {
        "description": "Wi-Fi network connection information.",
        "purpose": "A compatible device may use it to connect to a wireless network.",
        "action": "Connect only to a network you recognise and trust."
    },
    "CONTACT": {
        "description": "Contact information such as a vCard or MECARD.",
        "purpose": "A device may offer to save the contact details.",
        "action": "Verify the person's identity before saving or contacting them."
    },
    "EMAIL": {
        "description": "An email composition instruction.",
        "purpose": "It may open an email application with a recipient, subject or message.",
        "action": "Check the recipient and message before sending."
    },
    "EMAIL_ADDRESS": {
        "description": "An email address.",
        "purpose": "It can be used as an email destination.",
        "action": "Verify the address before sending sensitive information."
    },
    "PHONE": {
        "description": "A telephone call destination.",
        "purpose": "It may prompt your device to call a phone number.",
        "action": "Verify the number before making a call."
    },
    "PHONE_NUMBER": {
        "description": "A phone number encoded in the QR.",
        "purpose": "It may be used to contact a person or organisation.",
        "action": "Verify the number before calling."
    },
    "SMS": {
        "description": "An instruction to prepare a text message.",
        "purpose": "It may open the messaging application with a recipient and message.",
        "action": "Review the recipient and message before sending."
    },
    "LOCATION": {
        "description": "Geographic coordinates or a location link.",
        "purpose": "It may open a map or display a geographic destination.",
        "action": "Check the location before travelling or sharing it."
    },
    "CRYPTO_PAYMENT": {
        "description": "Cryptocurrency wallet or payment information.",
        "purpose": "It may be used to prepare a cryptocurrency transfer.",
        "action": "Independently verify the wallet address and amount before transferring funds."
    },
    "AUTHENTICATION": {
        "description": "An authenticator setup QR containing security information.",
        "purpose": "It may be used to configure an authenticator application.",
        "action": "Keep the authentication secret private. Never share this QR."
    },
    "UNKNOWN_URI": {
        "description": "A URI using a format not recognised by the current system.",
        "purpose": "Its intended action could not be reliably identified.",
        "action": "Do not open or execute it automatically."
    },
    "TEXT": {
        "description": "Plain text or information in an unrecognised QR format.",
        "purpose": "It displays the text encoded in the QR.",
        "action": "Read the content carefully and avoid following suspicious instructions."
    },
    "EMPTY": {
        "description": "No QR content was provided.",
        "purpose": "No action could be identified.",
        "action": "Upload a valid QR code image."
    }
}


# ==========================================
# SECURITY CONFIGURATION
# ==========================================

SENSITIVE_KEYS = (
    "password",
    "passwd",
    "secret",
    "token",
    "otp",
    "credential",
    "authorization",
    "auth_key"
)

URL_TYPES = {
    "URL",
    "PAYMENT_URL",
    "WHATSAPP_GROUP",
    "WHATSAPP_CHAT"
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
    "rb.gy",
    "rebrand.ly",
    "ow.ly",
    "buff.ly"
}


# ==========================================
# PRIVACY FILTERING
# ==========================================

def sanitize_details(value, parent_key=""):
    """
    Hide sensitive credential values recursively.
    """

    key = str(parent_key).lower()

    if any(item in key for item in SENSITIVE_KEYS):
        return "[Sensitive information hidden]"

    if isinstance(value, dict):
        return {
            child_key: sanitize_details(child_value, str(child_key))
            for child_key, child_value in value.items()
        }

    if isinstance(value, list):
        return [
            sanitize_details(item, parent_key)
            for item in value
        ]

    return value


# ==========================================
# URL METADATA
# ==========================================

def _get_url_metadata(content):
    """
    Extract basic URL metadata without exposing
    paths, query parameters or credentials.
    """

    try:
        parsed = urlsplit(content)

        hostname = parsed.hostname or ""
        domain = hostname.lower().rstrip(".")

        if not domain:
            return {}

        try:
            ipaddress.ip_address(domain)
            host_is_ip = True
        except ValueError:
            host_is_ip = False

        return {
            "domain": domain[:253],
            "scheme": parsed.scheme.lower()[:20],
            "uses_https": parsed.scheme.lower() == "https",
            "host_is_ip": host_is_ip,
            "has_shortener": domain in URL_SHORTENERS
        }

    except (ValueError, TypeError):
        return {}


# ==========================================
# REDIRECT ANALYSIS
# ==========================================

def get_redirect_analysis(content, qr_type):
    """
    Inspect redirects for supported URL-based QR codes.
    """

    if qr_type not in URL_TYPES:
        return {
            "status": "NOT_APPLICABLE",
            "message": "Redirect inspection is not applicable.",
            "redirect_count": 0,
            "redirect_chain": [],
            "final_domain": None
        }

    try:
        result = inspect_redirects(content)

        if not isinstance(result, dict):
            raise ValueError("Invalid redirect analyzer response.")

        return result

    except Exception as error:
        print(
            "REDIRECT ANALYSIS ERROR:",
            repr(error),
            flush=True
        )

        return {
            "status": "UNAVAILABLE",
            "message": "Redirect inspection could not be completed.",
            "redirect_count": 0,
            "redirect_chain": [],
            "final_domain": None
        }


# ==========================================
# GEMINI CONTEXT BUILDER
# ==========================================

def _build_gemini_context(
    qr_type,
    details,
    risk_result,
    information,
    content,
    redirect_analysis=None
):
    """
    Build an allowlisted, privacy-conscious context for Gemini.

    Raw QR content, passwords, contact details, payment identifiers
    and authentication secrets are never included.
    """

    findings = risk_result.get("findings", [])

    local_findings = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        local_findings.append({
            "title": str(
                finding.get("title", "Security finding")
            )[:150],
            "severity": str(
                finding.get("severity", "UNKNOWN")
            )[:20]
        })

    context = {
        "content_category": qr_type,
        "purpose": information["purpose"],
        "local_risk_level": risk_result.get(
            "risk_level",
            "INCONCLUSIVE"
        ),
        "local_findings": local_findings,
        "suspicious_indicators": [
            item["title"]
            for item in local_findings
            if item["severity"] in ("HIGH", "MEDIUM", "LOW")
        ]
    }

    # Website, payment URL and WhatsApp metadata.
    if qr_type in URL_TYPES:
        context.update(_get_url_metadata(content))

    # UPI: disclose only whether values exist.
    if qr_type in ("UPI", "UPI_PAYMENT", "UPI_ID"):
        context["has_amount"] = bool(details.get("amount"))
        context["recipient_present"] = bool(
            details.get("upi_id") or details.get("payee_name")
        )

    # Do not send actual messages or email contents.
    if qr_type in ("TEXT", "SMS", "EMAIL"):
        context["message_summary"] = (
            "Content was examined locally. "
            "Raw text and message contents were withheld for privacy."
        )

    # Include redirect metadata, not full URLs.
    if isinstance(redirect_analysis, dict):

        context["redirect_status"] = redirect_analysis.get(
            "status",
            "UNKNOWN"
        )

        context["redirect_count"] = redirect_analysis.get(
            "redirect_count",
            0
        )

        context["final_domain"] = redirect_analysis.get(
            "final_domain"
        )

        redirect_chain = redirect_analysis.get(
            "redirect_chain",
            []
        )

        context["redirect_domains"] = [
            item.get("to_domain")
            for item in redirect_chain
            if isinstance(item, dict) and item.get("to_domain")
        ]

    return context


def sanitize_decoded_payload(content, qr_type):
    """Return a locally displayable decoded payload with credential values masked."""
    text = str(content or "")[:5000]
    kind = str(qr_type or "").upper()

    # Wi-Fi QR credentials must never be rendered in the report.
    if kind == "WIFI":
        text = re.sub(r"(?i)(;P[:=])(.*?)(;|$)", r"\1[hidden]\3", text)

    # Authenticator and URI query secrets.
    text = re.sub(
        r"(?i)([?&;](?:secret|token|access_token|password|passwd|otp|code|signature|sig|key)=)[^&;]*",
        r"\1[hidden]", text
    )

    # Common free-text credential patterns.
    text = re.sub(
        r"(?i)\b(password|passwd|otp|pin|secret|access[_ -]?token)\s*[:=]\s*([^\s;,]+)",
        r"\1=[hidden]", text
    )

    # Avoid leaking URL user-info or credentials embedded in a URL.
    if kind in URL_TYPES or kind in {"UNKNOWN_URI", "PAYMENT_URL"}:
        try:
            parsed = urlsplit(text)
            if parsed.scheme and parsed.netloc:
                host = parsed.hostname or ""
                if parsed.port:
                    host = f"{host}:{parsed.port}"
                query = []
                for key, value in parse_qsl(parsed.query, keep_blank_values=True):
                    if re.search(r"password|passwd|secret|token|otp|auth|key|code|sig", key, re.I):
                        value = "[hidden]"
                    query.append((key, value))
                text = urlunsplit((parsed.scheme, host, parsed.path, urlencode(query), ""))
        except Exception:
            pass
    return text


# ==========================================
# MAIN QR ANALYSIS FUNCTION
# ==========================================

def analyze_qr_content(
    content: str,
    external_check=None,
    language="English"
) -> dict:

    # ==========================================
    # 1. HANDLE EMPTY INPUT
    # ==========================================

    if not isinstance(content, str) or not content.strip():

        risk_result = analyze_qr_risk(
            content="",
            qr_type="EMPTY",
            details={},
            external_check=external_check
        )

        return {
            "success": False,
            "message": "QR content is empty.",
            "qr_type": "EMPTY",
            "description": QR_INFORMATION["EMPTY"]["description"],
            "purpose": QR_INFORMATION["EMPTY"]["purpose"],
            "recommended_action": QR_INFORMATION["EMPTY"]["action"],
            "details": {},
            "security_status": "NOT_CHECKED",
            "redirect_analysis": {
                "status": "NOT_APPLICABLE"
            },
            "risk_analysis": risk_result,
            "ai_analysis": {
                "status": "NOT_APPLICABLE",
                "message": (
                    "AI analysis was skipped because no QR content "
                    "was provided."
                )
            }
        }

    content = content.strip()

    # ==========================================
    # 2. CLASSIFY QR CONTENT
    # ==========================================

    try:
        qr_type = classify_qr_content(content)

        if not isinstance(qr_type, str) or not qr_type.strip():
            qr_type = "UNKNOWN_URI"

    except Exception as error:
        print(
            "QR CLASSIFICATION ERROR:",
            repr(error),
            flush=True
        )
        qr_type = "UNKNOWN_URI"

    # ==========================================
    # 3. PARSE QR CONTENT
    # ==========================================

    try:
        parsed_result = parse_qr_content(content, qr_type)

        if not isinstance(parsed_result, dict):
            parsed_result = {}

        details = parsed_result.get("extracted_details", {})

        if not isinstance(details, dict):
            details = {}

    except Exception as error:
        print(
            "QR PARSING ERROR:",
            repr(error),
            flush=True
        )
        details = {}

    safe_details = sanitize_details(details)

    # ==========================================
    # 4. LOCAL RISK ENGINE
    # ==========================================

    try:
        risk_result = analyze_qr_risk(
            content=content,
            qr_type=qr_type,
            details=details,
            external_check=external_check
        )

        if not isinstance(risk_result, dict):
            raise ValueError("Risk engine returned invalid response.")

    except Exception as error:
        print(
            "RISK ENGINE ERROR:",
            repr(error),
            flush=True
        )

        risk_result = {
            "risk_level": "INCONCLUSIVE",
            "risk_score": 0,
            "score_is_probability": False,
            "assessment_status": "ANALYSIS_ERROR",
            "findings": [],
            "recommendation": (
                "The local security assessment failed. "
                "Do not assume this QR code is safe."
            )
        }

    # ==========================================
    # 5. QR-SPECIFIC INFORMATION
    # ==========================================

    information = QR_INFORMATION.get(
        qr_type,
        {
            "description": (
                "QR content detected, but its exact format "
                "is not recognised."
            ),
            "purpose": (
                "The intended action could not be identified reliably."
            ),
            "action": (
                "Do not follow unexpected instructions or "
                "open unknown destinations."
            )
        }
    )

    # ==========================================
    # 6. REDIRECT ANALYSIS
    # ==========================================

    redirect_analysis = get_redirect_analysis(
        content=content,
        qr_type=qr_type
    )

    # ==========================================
    # 7. EXTERNAL SECURITY STATUS
    # ==========================================

    external_status = (
        external_check.get("status")
        if isinstance(external_check, dict)
        else None
    )

    if external_status == "THREAT_FOUND":
        security_status = "KNOWN_THREAT_DETECTED"

    elif external_status == "NO_KNOWN_THREAT_FOUND":
        security_status = "NO_KNOWN_THREAT_FOUND"

    elif external_status == "UNAVAILABLE":
        security_status = "EXTERNAL_CHECK_UNAVAILABLE"

    else:
        security_status = "NOT_CHECKED"

    # ==========================================
    # 8. GEMINI AI ANALYSIS
    # ==========================================

    ai_analysis = {
        "status": "UNAVAILABLE",
        "message": "AI analysis is currently unavailable."
    }

    # Confirmed external threats take priority.
    if external_status == "THREAT_FOUND" and qr_type in URL_TYPES:

        ai_analysis = {
            "status": "SKIPPED",
            "message": (
                "AI analysis was skipped because the external "
                "security service identified a known threat."
            )
        }

    elif analyze_with_gemini is None:

        ai_analysis = {
            "status": "UNAVAILABLE",
            "message": "Gemini module could not be loaded."
        }

    else:

        try:
            safe_context = _build_gemini_context(
                qr_type=qr_type,
                details=details,
                risk_result=risk_result,
                information=information,
                content=content,
                redirect_analysis=redirect_analysis
            )

            ai_analysis = analyze_with_gemini(
                qr_type=qr_type,
                safe_context=safe_context,
                language=language
            )

            if not isinstance(ai_analysis, dict):
                ai_analysis = {
                    "status": "ERROR",
                    "message": "Gemini returned an invalid response."
                }

        except Exception as error:
            print(
                "GEMINI INTEGRATION ERROR:",
                repr(error),
                flush=True
            )

            ai_analysis = {
                "status": "UNAVAILABLE",
                "message": "AI explanation is currently unavailable."
            }

    # ==========================================
    # 9. FINAL RESPONSE
    # ==========================================

    return {
        "success": True,
        "qr_type": qr_type,
        "description": information["description"],
        "purpose": information["purpose"],
        "recommended_action": information["action"],
        "details": safe_details,
        # The exact decoded payload is retained for local display only after
        # masking credential-like values. It is not sent to Gemini or threat APIs.
        "decoded_content": sanitize_decoded_payload(content, qr_type),
        "security_status": security_status,

        # Redirect chain and final destination.
        "redirect_analysis": redirect_analysis,

        # Primary local security assessment.
        "risk_analysis": risk_result,

        # Secondary AI explanation.
        "ai_analysis": ai_analysis
    }
