
import os
import requests
from pathlib import Path
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load API key from the project-root .env file
PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"
load_dotenv(dotenv_path=ENV_FILE, override=True)

API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)


def check_url(url: str) -> dict:

    if not API_KEY:
        return {
            "status": "UNAVAILABLE",
            "message": "Google Safe Browsing API key is not configured."
        }

    if not isinstance(url, str) or not url.strip():
        return {
            "status": "UNAVAILABLE",
            "message": "No URL was provided."
        }

    url = url.strip()
    parsed = urlparse(url)

    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        return {
            "status": "UNAVAILABLE",
            "message": "Invalid HTTP or HTTPS URL."
        }

    payload = {
        "client": {
            "clientId": "trustcheck-qr-module",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": [
                "ANY_PLATFORM"
            ],
            "threatEntryTypes": [
                "URL"
            ],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        response = requests.post(
            SAFE_BROWSING_URL,
            params={"key": API_KEY},
            json=payload,
            timeout=15
        )

        response.raise_for_status()
        data = response.json()

        matches = data.get("matches", [])

        if matches:
            threat_types = sorted({
                match.get("threatType")
                for match in matches
                if match.get("threatType")
            })

            matched_urls = [
                match.get("threat", {}).get("url")
                for match in matches
                if match.get("threat", {}).get("url")
            ]

            return {
                "status": "THREAT_FOUND",
                "message": "Google Safe Browsing found a known threat.",
                "threat_types": threat_types,
                "matched_urls": matched_urls,
                "source": "Google Safe Browsing"
            }

        return {
            "status": "NO_KNOWN_THREAT_FOUND",
            "message": "No known threat was found in Google's current check.",
            "threat_types": [],
            "source": "Google Safe Browsing"
        }

    except requests.exceptions.Timeout:
        return {
            "status": "UNAVAILABLE",
            "message": "Google Safe Browsing request timed out."
        }

    except requests.exceptions.HTTPError as error:
        status_code = error.response.status_code
        return {
            "status": "UNAVAILABLE",
            "message": f"Google Safe Browsing HTTP error: {status_code}",
            "details": error.response.text[:500]
        }

    except requests.exceptions.RequestException as error:
        return {
            "status": "UNAVAILABLE",
            "message": f"Could not connect to Google Safe Browsing: {error}"
        }

    except (ValueError, TypeError):
        return {
            "status": "UNAVAILABLE",
            "message": "Google Safe Browsing returned an invalid response."
        }
