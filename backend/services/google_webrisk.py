"""Google Web Risk integration will be implemented here.

Only send supported web URLs to Web Risk. Never send Wi-Fi passwords,
UPI PINs, OTPs, contact details or other non-URL QR payloads.
Keep the API key in backend/.env and never commit that file.
"""


def check_url_with_google_webrisk(url: str) -> dict:
    return {
        "status": "UNAVAILABLE",
        "provider": "Google Web Risk",
        "threats": [],
        "message": "Google Web Risk is not configured yet."
    }
