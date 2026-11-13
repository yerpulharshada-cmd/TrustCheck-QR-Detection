
from backend.qr_module.threat_checker import check_url

print("\n===== GOOGLE SAFE BROWSING API TEST =====")

test_url = "https://www.google.com/"

result = check_url(test_url)

print("\nTest URL:", test_url)
print("API Result:", result)

print("\n===== TEST COMPLETED =====")
