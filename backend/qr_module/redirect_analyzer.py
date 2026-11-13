
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import requests


MAX_REDIRECTS = 5
REQUEST_TIMEOUT = (3, 5)

REDIRECT_CODES = {301, 302, 303, 307, 308}


def validate_public_url(url):
    """
    Validate an HTTP(S) URL and reject private or internal destinations.
    """

    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in {"http", "https"}:
            return False, "Unsupported URL scheme."

        if not parsed.hostname:
            return False, "URL hostname is missing."

        if parsed.username or parsed.password:
            return False, "URLs containing embedded credentials are blocked."

        hostname = parsed.hostname

        if hostname.lower() == "localhost" or hostname.lower().endswith(".localhost"):
            return False, "Localhost destinations are blocked."

        # Resolve hostname and reject non-public IP addresses.
        try:
            addresses = socket.getaddrinfo(
                hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM
            )
        except socket.gaierror:
            return False, "Hostname could not be resolved."

        if not addresses:
            return False, "No IP addresses were found."

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                return False, "Private or non-public network destinations are blocked."

        return True, "URL passed basic destination validation."

    except Exception:
        return False, "Invalid URL."


def inspect_redirects(url):
    """
    Inspect a URL's redirect chain without downloading webpage content.

    Returns redirect domains and HTTP status information.
    """

    current_url = url
    redirect_chain = []
    session = requests.Session()

    # Do not inherit system proxy settings.
    session.trust_env = False

    try:
        for step in range(MAX_REDIRECTS + 1):

            valid, message = validate_public_url(current_url)

            if not valid:
                return {
                    "status": "BLOCKED",
                    "message": message,
                    "redirect_count": len(redirect_chain),
                    "redirect_chain": redirect_chain,
                    "final_domain": None
                }

            parsed = urlsplit(current_url)
            current_domain = parsed.hostname.lower()

            try:
                # Stream response and do not download the page body.
                response = session.get(
                    current_url,
                    allow_redirects=False,
                    timeout=REQUEST_TIMEOUT,
                    stream=True,
                    headers={
                        "User-Agent": "TrustCheck-Security-Scanner/1.0",
                        "Range": "bytes=0-0"
                    }
                )

            except requests.RequestException:
                return {
                    "status": "UNAVAILABLE",
                    "message": "The destination could not be reached safely.",
                    "redirect_count": len(redirect_chain),
                    "redirect_chain": redirect_chain,
                    "final_domain": None
                }

            status_code = response.status_code
            location = response.headers.get("Location")
            response.close()

            if status_code not in REDIRECT_CODES:
                return {
                    "status": "COMPLETED",
                    "message": "Redirect inspection completed.",
                    "redirect_count": len(redirect_chain),
                    "redirect_chain": redirect_chain,
                    "final_domain": current_domain,
                    "final_http_status": status_code
                }

            if not location:
                return {
                    "status": "INCOMPLETE",
                    "message": "Redirect response did not contain a destination.",
                    "redirect_count": len(redirect_chain),
                    "redirect_chain": redirect_chain,
                    "final_domain": current_domain
                }

            next_url = urljoin(current_url, location)

            next_parsed = urlsplit(next_url)

            redirect_chain.append({
                "from_domain": current_domain,
                "to_domain": next_parsed.hostname,
                "http_status": status_code
            })

            current_url = next_url

        return {
            "status": "LIMIT_REACHED",
            "message": "Maximum redirect limit reached.",
            "redirect_count": len(redirect_chain),
            "redirect_chain": redirect_chain,
            "final_domain": None
        }

    finally:
        session.close()
