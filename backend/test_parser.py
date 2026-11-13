
from backend.qr_module.classifier import classify_qr_content
from backend.qr_module.parser import parse_qr_content


test_cases = [
    "https://example.com",

    "https://chat.whatsapp.com/abc123456",

    "upi://pay?pa=merchant@bank&pn=Test%20Shop&am=250&cu=INR&tn=Shopping",

    "WIFI:T:WPA;S=HomeNetwork;P=MyPassword123;;",

    "mailto:hello@example.com?subject=Hello&body=Test",

    "tel:+919876543210",

    "smsto:9876543210:Hello",

    "geo:17.385,78.486",

    "bitcoin:walletaddress",

    "Hello from TrustCheck"
]


for content in test_cases:

    qr_type = classify_qr_content(content)

    result = parse_qr_content(content, qr_type)

    print("\nQR TYPE:", qr_type)
    print("EXTRACTED DETAILS:", result["extracted_details"])
    print("-" * 60)
