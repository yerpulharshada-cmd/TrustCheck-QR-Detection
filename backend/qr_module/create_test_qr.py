import qrcode

url = "https://www.google.com/"

qr = qrcode.make(url)
qr.save("test_qr.png")

print("Test QR generated successfully!")