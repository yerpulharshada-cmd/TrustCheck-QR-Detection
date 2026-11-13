
import cv2
import numpy as np
import zxingcpp

from PIL import Image, ImageOps
from io import BytesIO
from arbez import Scanner


def add_unique(results, content):
    """Add decoded content without duplicates."""
    if isinstance(content, str):
        content = content.strip()

        if content and content not in results:
            results.append(content)


def prepare_image_variants(image_cv):
    """Create different image versions to improve QR decoding."""

    variants = [image_cv]

    gray = cv2.cvtColor(image_cv, cv2.COLOR_BGR2GRAY)
    variants.append(gray)

    # Contrast enhancement
    clahe = cv2.createCLAHE(
        clipLimit=2.0,
        tileGridSize=(8, 8)
    )
    enhanced = clahe.apply(gray)
    variants.append(enhanced)

    # Otsu threshold
    _, otsu = cv2.threshold(
        enhanced,
        0,
        255,
        cv2.THRESH_BINARY + cv2.THRESH_OTSU
    )
    variants.append(otsu)

    # Adaptive threshold
    adaptive = cv2.adaptiveThreshold(
        enhanced,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        31,
        5
    )
    variants.append(adaptive)

    # Sharpen image
    kernel = np.array([
        [0, -1, 0],
        [-1, 5, -1],
        [0, -1, 0]
    ])
    sharpened = cv2.filter2D(image_cv, -1, kernel)
    variants.append(sharpened)

    # Enlarge small QR images
    height, width = gray.shape

    if max(height, width) < 1200:
        enlarged = cv2.resize(
            image_cv,
            None,
            fx=2,
            fy=2,
            interpolation=cv2.INTER_CUBIC
        )
        variants.append(enlarged)

    return variants


def decode_with_zxing(variants, results, errors):
    """Decode QR codes using ZXing-C++."""

    for index, variant in enumerate(variants):

        try:
            decoded_items = zxingcpp.read_barcodes(variant)

            for item in decoded_items:
                if item.text:
                    add_unique(results, item.text)

        except Exception as error:
            errors.append(
                f"ZXing variant {index}: {type(error).__name__}"
            )


def decode_with_opencv(variants, results, errors):
    """Decode multiple and individual QR codes using OpenCV."""

    for index, variant in enumerate(variants):

        detector = cv2.QRCodeDetector()

        # Multiple QR detection
        try:
            success, texts, points, _ = (
                detector.detectAndDecodeMulti(variant)
            )

            if success and texts is not None:
                for content in texts:
                    add_unique(results, content)

        except Exception as error:
            errors.append(
                f"OpenCV multi {index}: {type(error).__name__}"
            )

        # Single QR fallback
        try:
            content, points, _ = detector.detectAndDecode(variant)
            add_unique(results, content)

        except Exception as error:
            errors.append(
                f"OpenCV single {index}: {type(error).__name__}"
            )


def decode_with_arbez(image_bytes, results, errors):
    """Decode using Arbez."""

    scanner = None

    try:
        scanner = Scanner()
        scan_result = scanner.scan(image_bytes)

        for detection in scan_result.detections:
            add_unique(results, detection.payload)

    except Exception as error:
        errors.append(
            f"Arbez: {type(error).__name__}"
        )

    finally:
        if scanner is not None:
            try:
                scanner.close()
            except Exception:
                pass


def decode_qr_image(image_bytes):

    results = []
    errors = []

    # 1. Validate image
    try:
        if not image_bytes:
            raise ValueError("Empty image")

        image = Image.open(
            BytesIO(image_bytes)
        )

        image = ImageOps.exif_transpose(image)

        if image.width * image.height > 25_000_000:
            raise ValueError("Image dimensions too large")

        image = image.convert("RGB")

        image_array = np.array(image)

        image_cv = cv2.cvtColor(
            image_array,
            cv2.COLOR_RGB2BGR
        )

    except Exception:
        return {
            "success": False,
            "message": "Invalid or unreadable image.",
            "results": [],
            "decoder": "Arbez + ZXing-C++ + OpenCV"
        }

    # 2. Create enhanced image versions
    try:
        variants = prepare_image_variants(image_cv)

    except Exception:
        variants = [image_cv]

    # 3. Run every decoder
    decode_with_arbez(
        image_bytes,
        results,
        errors
    )

    decode_with_zxing(
        variants,
        results,
        errors
    )

    decode_with_opencv(
        variants,
        results,
        errors
    )

    # 4. Return results
    if not results:
        return {
            "success": False,
            "message": (
                "QR image received, but its contents "
                "could not be decoded."
            ),
            "results": [],
            "total_qr_codes": 0,
            "decoder": "Arbez + ZXing-C++ + OpenCV",
            "errors": errors
        }

    return {
        "success": True,
        "message": "QR code decoding completed.",
        "total_qr_codes": len(results),
        "results": results,
        "decoder": "Arbez + ZXing-C++ + OpenCV"
    }
