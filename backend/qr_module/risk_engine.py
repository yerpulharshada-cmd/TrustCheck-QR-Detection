
import ipaddress
from urllib.parse import urlsplit


# ==========================================
# 1. SECURITY CONFIGURATION
# ==========================================

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify your account",
    "account suspended",
    "claim your reward",
    "winner",
    "prize",
    "limited time",
    "send otp",
    "share otp",
    "password",
    "bank details",
    "kyc update",
    "pay immediately",
    "avoid account closure",
    "free money",
    "investment guaranteed",
    "double your money"
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "shorturl.at", "rb.gy",
    "rebrand.ly", "ow.ly", "buff.ly"
}

URL_TYPES = {
    "URL",
    "PAYMENT_URL",
    "WHATSAPP_GROUP",
    "WHATSAPP_CHAT"
}

TEXT_TYPES = {
    "TEXT",
    "SMS",
    "EMAIL",
    "CALENDAR",
    "EVENT"
}

SEVERITY_WEIGHTS = {
    "HIGH": 40,
    "MEDIUM": 15,
    "LOW": 5,
    "INFO": 0,
    "UNKNOWN": 0
}


# ==========================================
# 2. FINDING MANAGEMENT
# ==========================================

def add_finding(findings, title, explanation, severity):

    finding = {
        "title": title,
        "explanation": explanation,
        "severity": severity
    }

    # Prevent duplicate findings.
    if not any(
        item["title"] == title
        and item["severity"] == severity
        for item in findings
    ):
        findings.append(finding)


# ==========================================
# 3. URL ANALYSIS
# ==========================================

def analyze_url(content, findings):

    try:
        parsed = urlsplit(content)

        domain = (parsed.hostname or "").lower().rstrip(".")

        if parsed.scheme.lower() not in ("http", "https"):
            add_finding(
                findings,
                "Unsupported URL scheme",
                "The link does not use a standard HTTP or HTTPS scheme.",
                "MEDIUM"
            )

        if not domain:
            add_finding(
                findings,
                "Invalid website address",
                "A valid website hostname could not be identified.",
                "HIGH"
            )
            return

        # Embedded credentials
        if parsed.username is not None or parsed.password is not None:
            add_finding(
                findings,
                "Embedded URL credentials",
                "The URL contains username or password information.",
                "HIGH"
            )

        # Invalid or unusual port
        try:
            port = parsed.port

            if port and port not in (80, 443):
                add_finding(
                    findings,
                    "Non-standard website port",
                    f"The destination uses port {port}. Verify that this is expected.",
                    "LOW"
                )

        except ValueError:
            add_finding(
                findings,
                "Invalid URL port",
                "The URL contains an invalid port number.",
                "MEDIUM"
            )

        # HTTP
        if parsed.scheme.lower() == "http":
            add_finding(
                findings,
                "Website does not use HTTPS",
                "The connection does not use HTTPS. Information sent to this website may not be protected in transit.",
                "LOW"
            )

        # IP address
        try:
            ipaddress.ip_address(domain)

            add_finding(
                findings,
                "IP address used as website",
                "The destination uses an IP address instead of a conventional domain.",
                "MEDIUM"
            )

        except ValueError:
            pass

        # Shortened URL
        if domain in URL_SHORTENERS:
            add_finding(
                findings,
                "Shortened URL",
                "The destination is hidden behind a URL-shortening service. Verify the final destination.",
                "MEDIUM"
            )

        # Punycode
        if "xn--" in domain:
            add_finding(
                findings,
                "Encoded international domain",
                "The domain contains encoded international characters. Check for misleading lookalike characters.",
                "MEDIUM"
            )

        # Suspicious keywords
        suspicious_terms = [
            "login",
            "verify",
            "secure",
            "account",
            "banking",
            "password",
            "wallet",
            "payment",
            "reward",
            "claim"
        ]

        url_text = (
            domain + parsed.path + parsed.query
        ).lower()

        matching_terms = [
            term for term in suspicious_terms
            if term in url_text
        ]

        if matching_terms:
            add_finding(
                findings,
                "Sensitive-action keywords",
                "The URL contains words associated with account access, rewards or payments: "
                + ", ".join(matching_terms)
                + ". These words alone do not prove fraud.",
                "LOW"
            )

        # Complex subdomains
        if len(domain.split(".")) >= 5:
            add_finding(
                findings,
                "Unusually complex domain",
                "The domain contains several subdomain levels. Verify its actual registered domain.",
                "LOW"
            )

    except (ValueError, TypeError):
        add_finding(
            findings,
            "URL parsing failed",
            "The website address could not be parsed reliably.",
            "MEDIUM"
        )


# ==========================================
# 4. TEXT ANALYSIS
# ==========================================

def analyze_text(content, findings):

    lower_content = content.lower()

    matched = [
        keyword for keyword in SUSPICIOUS_KEYWORDS
        if keyword in lower_content
    ]

    if matched:
        add_finding(
            findings,
            "Potential scam language",
            "The QR contains phrases associated with urgency, account verification or suspicious payment requests: "
            + ", ".join(matched),
            "MEDIUM"
        )


# ==========================================
# 5. UPI ANALYSIS
# ==========================================

def analyze_upi(details, findings):

    upi_id = details.get("upi_id")
    amount = details.get("amount")
    payee = details.get("payee_name")

    if not upi_id:
        add_finding(
            findings,
            "UPI ID not identified",
            "A payment destination could not be extracted from the available information.",
            "UNKNOWN"
        )
    else:
        add_finding(
            findings,
            "UPI payment destination present",
            "A UPI ID is encoded in the QR. Its account ownership has not been independently verified.",
            "INFO"
        )

    if amount is not None and amount != "":
        try:
            numeric_amount = float(amount)

            if numeric_amount <= 0:
                add_finding(
                    findings,
                    "Unusual payment amount",
                    "The encoded payment amount is zero or negative.",
                    "HIGH"
                )
            else:
                add_finding(
                    findings,
                    "Payment amount present",
                    f"The QR contains a payment amount of {amount}. Verify it before authorising payment.",
                    "INFO"
                )

        except (ValueError, TypeError):
            add_finding(
                findings,
                "Invalid payment amount",
                "The encoded payment amount could not be interpreted reliably.",
                "MEDIUM"
            )

    if payee:
        add_finding(
            findings,
            "Payee name present",
            "A payee name is encoded in the QR, but the actual account holder has not been verified.",
            "INFO"
        )

    # Important: payment precautions are not automatically a threat.
    add_finding(
        findings,
        "Payment verification required",
        "Check the recipient name and amount displayed in your trusted UPI application. Never approve an unexpected collect request.",
        "INFO"
    )


# ==========================================
# 6. REDIRECT ANALYSIS
# ==========================================

def analyze_redirects(redirect_analysis, findings):

    if not isinstance(redirect_analysis, dict):
        return

    status = str(
        redirect_analysis.get("status", "UNKNOWN")
    ).upper()

    redirect_count = redirect_analysis.get(
        "redirect_count", 0
    )

    final_domain = redirect_analysis.get("final_domain")

    if status in ("UNAVAILABLE", "ERROR", "UNKNOWN"):
        add_finding(
            findings,
            "Redirect inspection unavailable",
            "The destination's redirect behavior could not be fully verified.",
            "UNKNOWN"
        )
        return

    if isinstance(redirect_count, int) and redirect_count > 0:
        add_finding(
            findings,
            "Website redirects detected",
            f"The QR destination passed through {redirect_count} redirect(s). Verify the final destination before proceeding.",
            "INFO"
        )

    if final_domain:
        add_finding(
            findings,
            "Final website destination identified",
            f"The redirect inspection identified the final domain as {str(final_domain)[:253]}. This does not establish that the website is safe.",
            "INFO"
        )


# ==========================================
# 7. MAIN RISK ENGINE
# ==========================================

def analyze_qr_risk(
    content,
    qr_type,
    details=None,
    external_check=None,
    redirect_analysis=None
):

    details = details if isinstance(details, dict) else {}
    findings = []

    external_status = (
        external_check.get("status")
        if isinstance(external_check, dict)
        else None
    )

    # --------------------------------------
    # Website and link analysis
    # --------------------------------------

    if qr_type in URL_TYPES:

        analyze_url(content, findings)

        if external_status == "THREAT_FOUND":
            add_finding(
                findings,
                "Known threat detected",
                "An external threat-intelligence service identified this URL on a known threat list. Avoid opening it.",
                "HIGH"
            )

        elif external_status == "NO_KNOWN_THREAT_FOUND":
            add_finding(
                findings,
                "No known threat match",
                "The external threat check found no known threat match. This does not guarantee safety.",
                "INFO"
            )

        elif external_status == "UNAVAILABLE":
            add_finding(
                findings,
                "External verification unavailable",
                "The external threat check could not be completed.",
                "UNKNOWN"
            )

        else:
            add_finding(
                findings,
                "URL not externally verified",
                "No external threat-intelligence result is available for this URL.",
                "UNKNOWN"
            )

        analyze_redirects(redirect_analysis, findings)

    # --------------------------------------
    # Text-bearing QR formats
    # --------------------------------------

    if qr_type in TEXT_TYPES:
        analyze_text(content, findings)

    # --------------------------------------
    # UPI
    # --------------------------------------

    if qr_type in ("UPI", "UPI_PAYMENT", "UPI_ID"):
        analyze_upi(details, findings)

    # --------------------------------------
    # Wi-Fi
    # --------------------------------------

    if qr_type == "WIFI":
        add_finding(
            findings,
            "Wi-Fi connection information",
            "This QR contains Wi-Fi connection details. Connect only to a network you recognise and trust.",
            "INFO"
        )

    # --------------------------------------
    # Contact
    # --------------------------------------

    if qr_type == "CONTACT":
        add_finding(
            findings,
            "Contact information detected",
            "Verify the person's identity before saving or contacting them.",
            "INFO"
        )

    # --------------------------------------
    # Email
    # --------------------------------------

    if qr_type == "EMAIL_ADDRESS":
        add_finding(
            findings,
            "Email address detected",
            "Verify the recipient before sending sensitive information.",
            "INFO"
        )

    # --------------------------------------
    # Phone
    # --------------------------------------

    if qr_type in ("PHONE", "PHONE_NUMBER"):
        add_finding(
            findings,
            "Phone number detected",
            "Verify the number before calling.",
            "INFO"
        )

    # --------------------------------------
    # Cryptocurrency
    # --------------------------------------

    if qr_type == "CRYPTO_PAYMENT":
        add_finding(
            findings,
            "Cryptocurrency payment information",
            "Verify the wallet address and amount independently. Cryptocurrency transfers may be irreversible.",
            "INFO"
        )

    # --------------------------------------
    # Authentication
    # --------------------------------------

    if qr_type == "AUTHENTICATION":
        add_finding(
            findings,
            "Sensitive authentication information",
            "This QR may contain an authentication secret. Keep it private and use it only with the intended authenticator.",
            "INFO"
        )

    # --------------------------------------
    # Location
    # --------------------------------------

    if qr_type == "LOCATION":
        add_finding(
            findings,
            "Location information detected",
            "Verify the destination before travelling or sharing your location.",
            "INFO"
        )

    # --------------------------------------
    # WhatsApp
    # --------------------------------------

    if qr_type in ("WHATSAPP_GROUP", "WHATSAPP_CHAT"):
        add_finding(
            findings,
            "WhatsApp destination detected",
            "Verify the group or contact before joining or sharing personal or financial information.",
            "INFO"
        )

    # --------------------------------------
    # Unknown URI
    # --------------------------------------

    if qr_type == "UNKNOWN_URI":
        add_finding(
            findings,
            "Unrecognised URI scheme",
            "The QR contains a URI format that the current system does not recognise. Do not execute it automatically.",
            "UNKNOWN"
        )

    # --------------------------------------
    # Calendar and event
    # --------------------------------------

    if qr_type in ("CALENDAR", "EVENT"):
        add_finding(
            findings,
            "Calendar or event information",
            "Review the event details, location and any embedded links before adding it to your calendar.",
            "INFO"
        )

    # --------------------------------------
    # Product and ISBN
    # --------------------------------------

    if qr_type in ("PRODUCT", "ISBN"):
        add_finding(
            findings,
            "Product identification information",
            "The QR contains product-related identification information. Verify product details with a trusted source.",
            "INFO"
        )

    # ======================================
    # 8. RISK SCORE
    # ======================================

    score = min(
        100,
        sum(
            SEVERITY_WEIGHTS.get(
                item["severity"], 0
            )
            for item in findings
        )
    )

    severities = {
        item["severity"] for item in findings
    }

    # ======================================
    # 9. RISK CLASSIFICATION
    # ======================================

    if external_status == "THREAT_FOUND" and qr_type in URL_TYPES:
        risk_level = "HIGH"

    elif "HIGH" in severities:
        risk_level = "HIGH"

    elif "MEDIUM" in severities:
        risk_level = "MEDIUM"

    elif "UNKNOWN" in severities:
        risk_level = "INCONCLUSIVE"

    elif qr_type in URL_TYPES:
        # A URL without threat intelligence is not verified safe.
        risk_level = "INCONCLUSIVE"

    else:
        risk_level = "LOW"

    # ======================================
    # 10. ASSESSMENT STATUS
    # ======================================

    if external_status == "THREAT_FOUND" and qr_type in URL_TYPES:
        assessment_status = "THREAT_DETECTED"

    elif external_status == "NO_KNOWN_THREAT_FOUND" and qr_type in URL_TYPES:
        assessment_status = "NO_KNOWN_THREAT_FOUND"

    elif external_status == "UNAVAILABLE" and qr_type in URL_TYPES:
        assessment_status = "EXTERNAL_CHECK_UNAVAILABLE"

    else:
        assessment_status = "RULE_BASED_ASSESSMENT"

    return {
        "risk_level": risk_level,
        "risk_score": score,
        "score_is_probability": False,
        "assessment_status": assessment_status,
        "findings": findings,
        "recommendation": get_recommendation(
            risk_level,
            qr_type
        )
    }


# ==========================================
# 11. RECOMMENDATIONS
# ==========================================

def get_recommendation(risk_level, qr_type):

    if risk_level == "HIGH":
        return (
            "Avoid opening this destination or proceeding with the requested action. "
            "Verify independently using an official source."
        )

    if risk_level == "MEDIUM":
        return (
            "Proceed cautiously. Verify the QR source, destination and requested action before proceeding."
        )

    if risk_level == "INCONCLUSIVE":
        return (
            "The available checks do not establish that this QR is safe. "
            "Verify its destination independently before proceeding."
        )

    if qr_type in ("UPI", "UPI_PAYMENT", "UPI_ID"):
        return (
            "Check the recipient name and amount in your trusted UPI application before authorising payment."
        )

    if qr_type == "WIFI":
        return "Connect only if you recognise and trust the Wi-Fi network."

    if qr_type == "AUTHENTICATION":
        return "Keep the authentication secret private and use it only with the intended authenticator."

    if qr_type in ("WHATSAPP_GROUP", "WHATSAPP_CHAT"):
        return "Verify the group or contact before joining or sharing information."

    return (
        "No significant suspicious indicators were detected by the checks performed. "
        "This does not guarantee that the QR is safe."
    )
