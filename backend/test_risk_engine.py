
from backend.qr_module.classifier import classify_qr_content
from backend.qr_module.parser import parse_qr_content
from backend.qr_module.risk_engine import analyze_qr_risk


test_cases = [
    "https://example.com",

    "https://bit.ly/example",

    "upi://pay?pa=merchant@bank&pn=TestShop&am=500",

    "You won a prize! Verify your account immediately and share OTP.",

    "WIFI:T:WPA;S:HomeNetwork;P:password123;;"
]


for content in test_cases:

    qr_type = classify_qr_content(content)

    parsed = parse_qr_content(content, qr_type)

    risk = analyze_qr_risk(
        content,
        qr_type,
       parsed.get("details", {})
    )

    print("\nQR TYPE:", qr_type)
    print("CONTENT:", content)
    print("RISK:", risk["risk_level"])
    print("SCORE:", risk["risk_score"])
    print("FINDINGS:")

    for finding in risk["findings"]:
        print("-", finding["title"])
        print(" ", finding["explanation"])

    print("ACTION:", risk["recommendation"])
    print("=" * 60)
