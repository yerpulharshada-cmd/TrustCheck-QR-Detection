
from backend.qr_module.classifier import classify_qr_content

test_cases = [
    "https://example.com",
    "https://chat.whatsapp.com/abc123",
    "https://wa.me/919876543210",
    "upi://pay?pa=test@bank",
    "WIFI:T:WPA;S:Home;P:12345678;;",
    "mailto:test@example.com",
    "tel:+919876543210",
    "smsto:9876543210:Hello",
    "geo:17.385,78.486",
    "bitcoin:walletaddress",
    "Hello, welcome to TrustCheck"
]

for content in test_cases:
    result = classify_qr_content(content)

    print("QR Content:", content)
    print("QR Type:", result)
    print("-" * 50)
