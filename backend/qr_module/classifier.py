
import re
from urllib.parse import urlsplit


def classify_qr_content(content: str) -> str:

    if not content or not content.strip():
        return "EMPTY"

    content = content.strip()
    lower_content = content.lower()

    if lower_content.startswith("wifi:"):
        return "WIFI"

    if lower_content.startswith("begin:vcard"):
        return "CONTACT"

    if lower_content.startswith("mecard:"):
        return "CONTACT"

    if lower_content.startswith(("upi://pay", "upi://collect")):
        return "UPI_PAYMENT"

    if lower_content.startswith("upi://"):
        return "UPI"

    # Validate the actual WhatsApp hostname.
    try:
        parsed_link = urlsplit(content)
        host = (parsed_link.hostname or "").lower()

        if parsed_link.scheme.lower() in ("http", "https"):

            if host == "chat.whatsapp.com":
                return "WHATSAPP_GROUP"

            if host in (
                "wa.me",
                "api.whatsapp.com",
                "www.whatsapp.com",
                "whatsapp.com"
            ):
                if host == "wa.me" or parsed_link.path.startswith("/send"):
                    return "WHATSAPP_CHAT"

    except ValueError:
        pass

    if lower_content.startswith(("mailto:", "matmsg:")):
        return "EMAIL"

    if lower_content.startswith("tel:"):
        return "PHONE"

    if lower_content.startswith(("sms:", "smsto:")):
        return "SMS"

    if lower_content.startswith("geo:"):
        return "LOCATION"

    crypto_schemes = (
        "bitcoin:",
        "ethereum:",
        "litecoin:",
        "dogecoin:",
        "bitcoincash:"
    )

    if lower_content.startswith(crypto_schemes):
        return "CRYPTO_PAYMENT"

    if lower_content.startswith("otpauth://"):
        return "AUTHENTICATION"

    # Website URLs and payment provider URLs.
    try:
        parsed = urlsplit(content)

        if parsed.scheme.lower() in ("http", "https") and parsed.hostname:

            domain = parsed.hostname.lower()

            payment_domains = (
                "paypal.com",
                "pay.google.com",
                "paytm.com",
                "phonepe.com",
                "razorpay.com",
                "cashfree.com",
                "stripe.com"
            )

            if any(
                domain == provider or domain.endswith("." + provider)
                for provider in payment_domains
            ):
                return "PAYMENT_URL"

            return "URL"

    except ValueError:
        pass

    # Check email before UPI because both contain @.
    email_pattern = (
        r"^[A-Za-z0-9._%+-]+@"
        r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    )

    if re.fullmatch(email_pattern, content):
        return "EMAIL_ADDRESS"

    upi_pattern = r"^[a-zA-Z0-9._-]{2,256}@[a-zA-Z0-9.-]{2,64}$"

    if re.fullmatch(upi_pattern, content):
        return "UPI_ID"

    phone_pattern = r"^\+?[0-9][0-9\s().-]{6,18}$"

    if re.fullmatch(phone_pattern, content):
        return "PHONE_NUMBER"

    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", content):
        return "UNKNOWN_URI"

    return "TEXT"
