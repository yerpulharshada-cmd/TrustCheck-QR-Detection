
import re
from urllib.parse import urlsplit, parse_qs, unquote


SENSITIVE_KEYS = {
    "token", "access_token", "auth", "authorization",
    "password", "passwd", "secret", "key", "code",
    "otp", "signature", "sig", "invite", "session"
}


def mask_sensitive_value(value):
    if not value:
        return value

    value = str(value)

    if len(value) <= 4:
        return "****"

    return value[:2] + "*" * min(len(value) - 4, 12) + value[-2:]


def decode_escaped(value):
    """Decode common escaped characters in QR formats."""
    replacements = {
        r"\n": "\n",
        r"\N": "\n",
        r"\;": ";",
        r"\,": ",",
        r"\:": ":",
        r"\\": "\\"
    }

    for old, new in replacements.items():
        value = value.replace(old, new)

    return value


def split_qr_fields(value):
    """Split semicolon-separated QR fields without splitting escaped semicolons."""
    return re.split(r"(?<!\\);", value)


def safe_url_details(content):
    parsed = urlsplit(content)
    query = {}

    for key, values in parse_qs(parsed.query).items():
        query[key] = (
            ["********"]
            if key.lower() in SENSITIVE_KEYS
            else values
        )

    return {
        "scheme": parsed.scheme,
        "domain": parsed.hostname,
        "path": parsed.path,
        "query_parameters": query
    }


def parse_wifi(content):
    fields = {}

    for item in split_qr_fields(content[5:].rstrip(";")):
        if ":" in item:
            key, value = item.split(":", 1)
            fields[key.upper()] = decode_escaped(value)

    return {
        "network_name": fields.get("S", "Not provided"),
        "security_type": fields.get("T", "Not specified"),
        "password": (
            mask_sensitive_value(fields["P"])
            if fields.get("P") else "Not provided"
        ),
        "hidden_network": fields.get("H", "false").lower() == "true",
        "identity": fields.get("I", "Not provided"),
        "warning": "Verify the network owner before connecting."
    }


def parse_vcard(content):
    details = {
        "name": None,
        "organisation": None,
        "title": None,
        "phone_numbers": [],
        "emails": [],
        "websites": [],
        "addresses": [],
        "notes": []
    }

    unfolded = re.sub(r"\r?\n[ \t]", "", content)

    for line in unfolded.splitlines():
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.split(";")[0].upper()
        value = decode_escaped(value.strip())

        if key == "FN":
            details["name"] = value
        elif key == "N" and not details["name"]:
            details["name"] = value.replace(";", " ")
        elif key == "ORG":
            details["organisation"] = value
        elif key == "TITLE":
            details["title"] = value
        elif key == "TEL":
            details["phone_numbers"].append(value)
        elif key == "EMAIL":
            details["emails"].append(value)
        elif key == "URL":
            details["websites"].append(value)
        elif key == "ADR":
            details["addresses"].append(value)
        elif key == "NOTE":
            details["notes"].append(value)

    return details


def parse_mecard(content):
    fields = {}

    body = content[len("MECARD:"):].rstrip(";")

    for item in split_qr_fields(body):
        if ":" in item:
            key, value = item.split(":", 1)
            key = key.upper()
            value = decode_escaped(value)

            if key in fields:
                if not isinstance(fields[key], list):
                    fields[key] = [fields[key]]
                fields[key].append(value)
            else:
                fields[key] = value

    def as_list(key):
        value = fields.get(key)
        if not value:
            return []
        return value if isinstance(value, list) else [value]

    return {
        "name": fields.get("N"),
        "formatted_name": fields.get("FN"),
        "organisation": fields.get("ORG"),
        "phone_numbers": as_list("TEL"),
        "emails": as_list("EMAIL"),
        "addresses": as_list("ADR"),
        "notes": fields.get("NOTE"),
        "websites": as_list("URL")
    }


def parse_calendar(content):
    details = {
        "event_name": None,
        "description": None,
        "location": None,
        "start": None,
        "end": None,
        "organizer": None,
        "attendees": []
    }

    unfolded = re.sub(r"\r?\n[ \t]", "", content)

    for line in unfolded.splitlines():
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        property_name = key.split(";")[0].upper()
        value = decode_escaped(value.strip())

        if property_name == "SUMMARY":
            details["event_name"] = value
        elif property_name == "DESCRIPTION":
            details["description"] = value
        elif property_name == "LOCATION":
            details["location"] = value
        elif property_name == "DTSTART":
            details["start"] = value
        elif property_name == "DTEND":
            details["end"] = value
        elif property_name == "ORGANIZER":
            details["organizer"] = value
        elif property_name == "ATTENDEE":
            details["attendees"].append(value)

    return details


def parse_email(content):
    if content.lower().startswith("mailto:"):
        parsed = urlsplit(content)
        params = parse_qs(parsed.query)

        return {
            "email_address": unquote(parsed.path),
            "subject": params.get("subject", [None])[0],
            "message": params.get("body", [None])[0]
        }

    if content.lower().startswith("matmsg:"):
        fields = {}

        for item in split_qr_fields(content[7:]):
            if ":" in item:
                key, value = item.split(":", 1)
                fields[key.upper()] = decode_escaped(value)

        return {
            "email_address": fields.get("TO"),
            "subject": fields.get("SUB"),
            "message": fields.get("BODY")
        }

    return {"email_address": content}


def parse_sms(content):
    value = content.split(":", 1)[1]

    if "?" in value:
        recipient, query = value.split("?", 1)
        params = parse_qs(query)

        return {
            "recipient_number": recipient,
            "message": params.get("body", [None])[0],
            "purpose": "Prepare an SMS message"
        }

    number, separator, message = value.partition(":")

    return {
        "recipient_number": number,
        "message": message if separator else None,
        "purpose": "Prepare an SMS message"
    }


def parse_location(content):
    value = content[4:].split("?", 1)[0]
    coordinates = value.split(",")

    latitude = coordinates[0] if coordinates else None
    longitude = coordinates[1] if len(coordinates) > 1 else None

    valid = False

    try:
        lat = float(latitude)
        lon = float(longitude)
        valid = -90 <= lat <= 90 and -180 <= lon <= 180
    except (TypeError, ValueError):
        pass

    return {
        "latitude": latitude,
        "longitude": longitude,
        "coordinates_valid": valid,
        "purpose": "Geographic location"
    }


def parse_crypto(content):
    parsed = urlsplit(content)

    return {
        "currency_scheme": parsed.scheme,
        "wallet_or_destination": parsed.path or parsed.netloc,
        "payment_parameters": {
            key: (
                ["********"]
                if key.lower() in SENSITIVE_KEYS
                else values
            )
            for key, values in parse_qs(parsed.query).items()
        },
        "warning": "Wallet ownership and payment legitimacy are not verified."
    }


def parse_authentication(content):
    parsed = urlsplit(content)
    params = parse_qs(parsed.query)

    return {
        "authentication_type": parsed.netloc,
        "account_label": unquote(parsed.path.lstrip("/")),
        "issuer": params.get("issuer", [None])[0],
        "algorithm": params.get("algorithm", [None])[0],
        "digits": params.get("digits", [None])[0],
        "period": params.get("period", [None])[0],
        "secret": "********" if params.get("secret") else "Not provided",
        "warning": "This QR may contain an authentication secret. Do not share it."
    }


def parse_qr_content(content: str, qr_type: str) -> dict:
    """Parse QR content into structured, privacy-conscious details."""

    content = content.strip()
    qr_type = (qr_type or "UNKNOWN").upper()

    details = {}

    if qr_type in ("URL", "PAYMENT_URL"):
        details = safe_url_details(content)

        if qr_type == "PAYMENT_URL":
            details["payment_link"] = True
            details["warning"] = (
                "The payment provider and merchant have not been verified."
            )

    elif qr_type == "UPI_PAYMENT":
        parsed = urlsplit(content)
        params = parse_qs(parsed.query)

        details = {
            "upi_id": params.get("pa", [None])[0],
            "payee_name": params.get("pn", [None])[0],
            "amount": params.get("am", [None])[0],
            "currency": params.get("cu", ["INR"])[0],
            "transaction_note": params.get("tn", [None])[0],
            "transaction_reference": params.get("tr", [None])[0],
            "merchant_code": params.get("mc", [None])[0],
            "transaction_purpose": params.get("purpose", [None])[0],
            "warning": "Verify the recipient and amount before authorising payment."
        }

    elif qr_type == "UPI_ID":
        details = {
            "upi_id": content,
            "purpose": "UPI payment address",
            "warning": "The account holder's identity is not verified."
        }

    elif qr_type == "WIFI":
        details = parse_wifi(content)

    elif qr_type == "CONTACT":
        if content.upper().startswith("BEGIN:VCARD"):
            details = parse_vcard(content)
        elif content.upper().startswith("MECARD:"):
            details = parse_mecard(content)

    elif qr_type in ("WHATSAPP_CHAT", "WHATSAPP_GROUP"):
        parsed = urlsplit(content)
        params = parse_qs(parsed.query)

        details = {
            "service": "WhatsApp",
            "domain": parsed.hostname,
            "purpose": (
                "Group invitation"
                if qr_type == "WHATSAPP_GROUP"
                else "Open a chat or prepare a message"
            ),
            "phone_number": (
                params.get("phone", [None])[0]
                if parsed.path.strip("/") == "send"
                else parsed.path.strip("/")
            ),
            "prefilled_message": params.get("text", [None])[0],
            "warning": "The recipient or group identity is not verified."
        }

        if qr_type == "WHATSAPP_GROUP":
            details["invitation_code"] = mask_sensitive_value(
                parsed.path.rstrip("/").split("/")[-1]
            )

    elif qr_type == "EMAIL":
        details = parse_email(content)

    elif qr_type in ("PHONE", "PHONE_NUMBER"):
        number = (
            content[4:]
            if content.lower().startswith("tel:")
            else content
        )

        details = {
            "phone_number": number,
            "purpose": "Phone call destination",
            "warning": "The identity of this phone number is not verified."
        }

    elif qr_type == "SMS":
        details = parse_sms(content)

    elif qr_type == "LOCATION":
        details = parse_location(content)

    elif qr_type == "CRYPTO_PAYMENT":
        details = parse_crypto(content)

    elif qr_type == "AUTHENTICATION":
        details = parse_authentication(content)

    elif qr_type in ("CALENDAR", "EVENT"):
        details = parse_calendar(content)

    elif qr_type == "UNKNOWN_URI":
        parsed = urlsplit(content)

        details = {
            "scheme": parsed.scheme,
            "purpose": "Unrecognised URI format",
            "warning": "Do not open or execute an unknown URI."
        }

    elif qr_type in ("TEXT", "PRODUCT", "ISBN", "UNKNOWN"):
        details = {
            "text": content,
            "purpose": "Readable QR content"
        }

    else:
        details = {
            "text": content,
            "purpose": "Unrecognised or unsupported QR content",
            "warning": "The content was decoded but its format is not fully understood."
        }

    return {
        "qr_type": qr_type,
        "extracted_details": details
    }
