from backend.qr_module.analyzer import analyze_qr_content


test_qr_codes = [
    "https://example.com",
    "upi://pay?pa=merchant@upi&pn=TestMerchant&am=500&cu=INR",
    "WIFI:T:WPA;S:TestWiFi;P:password123;;",
    "Hello! This is a sample QR code."
]

for content in test_qr_codes:

    print("\n" + "=" * 50)
    print("TESTING QR:", content)

    result = analyze_qr_content(content)

    print("QR TYPE:", result["qr_type"])
    print("DESCRIPTION:", result["description"])
    print("DETAILS:", result["details"])
    print("RISK ANALYSIS:", result["risk_analysis"])

