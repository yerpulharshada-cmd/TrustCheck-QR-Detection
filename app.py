import sys
import sqlite3
import hashlib
import html
from pathlib import Path
from datetime import datetime

import streamlit as st


# ============================================================
# TRUSTCHECK - STREAMLIT FRONTEND
# Uses the existing local QR decoder and analysis engine.
# Raw QR payloads are never written to scan history.
# ============================================================

APP_DIR = Path(__file__).resolve().parent
BACKEND_CANDIDATES = [
    APP_DIR,
    APP_DIR / "TrustCheck_QR_Module",
    APP_DIR.parent / "TrustCheck_QR_Module",
]
BACKEND_ROOT = next(
    (
        path for path in BACKEND_CANDIDATES
        if (path / "backend" / "qr_module" / "decoder.py").exists()
    ),
    None,
)

st.set_page_config(
    page_title="TrustCheck | QR Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

if BACKEND_ROOT is None:
    st.error(
        "TrustCheck backend folder was not found. Keep app.py beside the "
        "backend folder, or update BACKEND_CANDIDATES near the top of this file."
    )
    st.stop()

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

try:
    from backend.qr_module.decoder import decode_qr_image
    from backend.qr_module.analyzer import analyze_qr_content
except Exception as exc:
    st.error(f"Could not import the TrustCheck backend: {exc}")
    st.exception(exc)
    st.stop()


# ============================================================
# TRANSLATIONS - exactly English, Hindi and Marathi
# ============================================================

COPY = {
    "English": {
        "language": "English", "workspace": "WORKSPACE",
        "dashboard": "Dashboard", "scanner": "QR Scanner",
        "platform": "TRUSTCHECK SECURITY", "ready": "SYSTEM READY",
        "overview": "Security overview",
        "overview_sub": "A clear summary of QR codes analysed on this device.",
        "total": "Total scans", "low_count": "Low risk",
        "medium_count": "Medium risk", "high_count": "High risk",
        "distribution": "Risk distribution", "qr_types": "QR types analysed",
        "recent": "Recent scans", "no_history": "No scan history yet. Analyse a QR code to build your dashboard.",
        "scanner_title": "QR security scanner",
        "scanner_sub": "Upload a QR image to decode its contents and assess potential risks.",
        "upload_title": "Drop your QR image here",
        "upload_sub": "Choose an image from your device",
        "formats": "PNG, JPG or WEBP · Maximum 5 MB",
        "file": "Select QR image", "analyze": "Analyse QR code",
        "loading": "Decoding and checking locally first...",
        "remove": "Remove image", "report": "Individual QR analysis",
        "completed": "ANALYSIS COMPLETE", "qr": "QR code",
        "risk_heading": "SECURITY RISK LEVEL", "low": "LOW",
        "medium": "MEDIUM", "high": "HIGH",
        "inconclusive": "INCONCLUSIVE", "score": "Risk score",
        "out_of": "out of 100", "low_title": "No major warning signs detected",
        "medium_title": "Proceed with caution",
        "high_title": "Strong security warning detected",
        "inconclusive_title": "Assessment is inconclusive",
        "low_text": "No significant warning signs were found in the checks completed. This is not a guarantee of safety.",
        "medium_text": "Some warning signs or verification limitations need your attention. Check carefully before proceeding.",
        "high_text": "The available evidence indicates a potentially dangerous QR code. Do not follow its instructions.",
        "inconclusive_text": "There is not enough information to determine the risk confidently.",
        "contents": "What does this QR contain?",
        "purpose": "What is it used for?",
        "happens": "What happens when you use it?",
        "destination": "Where does it take you?",
        "original": "Original destination", "final": "Final destination",
        "redirect": "Redirect information",
        "not_confirmed": "The final destination could not be confirmed.",
        "no_destination": "No website destination was identified for this QR code.",
        "why": "Why this risk level?", "consequences": "What could happen?",
        "do": "What should you do?", "avoid": "What should you avoid?",
        "details": "Decoded information", "show": "Show decoded information",
        "no_findings": "No specific warning signs were returned by local checks. This does not prove the QR code is safe.",
        "no_info": "No additional explanation was provided.",
        "safe_action": "Verify the QR code source and all details independently before taking action.",
        "avoid_action": "Never share passwords, OTPs, UPI PINs or banking credentials. Do not approve unexpected payments or install unknown apps.",
        "incomplete": "Some checks could not be completed. This is a limitation of the assessment, not proof that the QR code is malicious or safe.",
        "url_warning": "Do not open an unfamiliar destination directly. Verify the website independently.",
        "safety": "TrustCheck provides guidance based on available evidence. It cannot guarantee that a QR code is safe.",
        "new_scan": "Scan another QR", "no_qr": "No QR code was detected in this image.",
        "error_size": "Image must be smaller than 5 MB.",
        "error_file": "Please upload a QR image first.",
        "error_analysis": "QR analysis failed. Please try again.",
        "footer": "TrustCheck · Scan smart. Stay safe.",
        "disclaimer": "Verify important requests independently. Never trust an unfamiliar QR code blindly.",
        "scan_date": "Scanned", "type": "Type",
        "checks_limited": "Verification incomplete",
        "dashboard_empty": "Statistics will appear after your first scan.",
        "open_scanner": "Open QR scanner",
        "no_decoded": "No decoded information available.",
        "unknown": "Unknown",
    },
    "Hindi": {
        "language": "हिन्दी", "workspace": "कार्य क्षेत्र",
        "dashboard": "डैशबोर्ड", "scanner": "QR स्कैनर",
        "platform": "TRUSTCHECK सुरक्षा", "ready": "सिस्टम तैयार",
        "overview": "सुरक्षा अवलोकन",
        "overview_sub": "इस डिवाइस पर विश्लेषित QR कोड का सारांश।",
        "total": "कुल स्कैन", "low_count": "कम जोखिम",
        "medium_count": "मध्यम जोखिम", "high_count": "उच्च जोखिम",
        "distribution": "जोखिम वितरण", "qr_types": "विश्लेषित QR प्रकार",
        "recent": "हाल के स्कैन", "no_history": "अभी कोई स्कैन इतिहास नहीं है। डैशबोर्ड शुरू करने के लिए QR कोड का विश्लेषण करें।",
        "scanner_title": "QR सुरक्षा स्कैनर",
        "scanner_sub": "QR की जानकारी पढ़ने और संभावित जोखिम जांचने के लिए तस्वीर अपलोड करें।",
        "upload_title": "QR की तस्वीर यहां डालें",
        "upload_sub": "अपने डिवाइस से तस्वीर चुनें",
        "formats": "PNG, JPG या WEBP · अधिकतम 5 MB",
        "file": "QR तस्वीर चुनें", "analyze": "QR कोड का विश्लेषण करें",
        "loading": "पहले स्थानीय स्तर पर QR पढ़कर जांच की जा रही है...",
        "remove": "तस्वीर हटाएं", "report": "QR विश्लेषण रिपोर्ट",
        "completed": "विश्लेषण पूरा", "qr": "QR कोड",
        "risk_heading": "सुरक्षा जोखिम स्तर", "low": "कम",
        "medium": "मध्यम", "high": "उच्च",
        "inconclusive": "अनिर्णायक", "score": "जोखिम स्कोर",
        "out_of": "100 में से", "low_title": "कोई बड़ा चेतावनी संकेत नहीं मिला",
        "medium_title": "सावधानी से आगे बढ़ें",
        "high_title": "गंभीर सुरक्षा चेतावनी मिली",
        "inconclusive_title": "जांच का परिणाम स्पष्ट नहीं है",
        "low_text": "पूरी की गई जांच में कोई बड़ा चेतावनी संकेत नहीं मिला। यह सुरक्षा की गारंटी नहीं है।",
        "medium_text": "कुछ चेतावनी संकेत या अधूरी जांच पर ध्यान देना आवश्यक है। आगे बढ़ने से पहले जांचें।",
        "high_text": "उपलब्ध जानकारी संभावित खतरे का संकेत देती है। QR के निर्देशों का पालन न करें।",
        "inconclusive_text": "जोखिम का भरोसेमंद निर्धारण करने के लिए पर्याप्त जानकारी उपलब्ध नहीं है।",
        "contents": "इस QR में क्या है?", "purpose": "इसका उपयोग किस लिए है?",
        "happens": "इस्तेमाल करने पर क्या होगा?",
        "destination": "यह आपको कहां ले जाएगा?",
        "original": "मूल गंतव्य", "final": "अंतिम गंतव्य",
        "redirect": "रीडायरेक्ट जानकारी",
        "not_confirmed": "अंतिम गंतव्य की पुष्टि नहीं हो सकी।",
        "no_destination": "इस QR के लिए वेबसाइट का गंतव्य नहीं मिला।",
        "why": "यह जोखिम स्तर क्यों है?", "consequences": "क्या नुकसान हो सकता है?",
        "do": "आपको क्या करना चाहिए?", "avoid": "आपको क्या नहीं करना चाहिए?",
        "details": "पढ़ी गई जानकारी", "show": "पढ़ी गई जानकारी देखें",
        "no_findings": "स्थानीय जांच में कोई विशेष चेतावनी संकेत नहीं मिला। यह QR के सुरक्षित होने का प्रमाण नहीं है।",
        "no_info": "अतिरिक्त विवरण उपलब्ध नहीं है।",
        "safe_action": "कोई कदम उठाने से पहले QR के स्रोत और जानकारी की स्वतंत्र रूप से पुष्टि करें।",
        "avoid_action": "पासवर्ड, OTP, UPI PIN या बैंकिंग जानकारी साझा न करें। अनजान भुगतान मंजूर न करें और अज्ञात ऐप इंस्टॉल न करें।",
        "incomplete": "कुछ जांच पूरी नहीं हो सकीं। यह जांच की सीमा है, QR के खतरनाक या सुरक्षित होने का प्रमाण नहीं।",
        "url_warning": "अनजान लिंक सीधे न खोलें। वेबसाइट की स्वतंत्र रूप से पुष्टि करें।",
        "safety": "TrustCheck उपलब्ध जानकारी के आधार पर मार्गदर्शन देता है; सुरक्षा की गारंटी नहीं।",
        "new_scan": "दूसरा QR स्कैन करें", "no_qr": "इस तस्वीर में QR कोड नहीं मिला।",
        "error_size": "तस्वीर 5 MB से छोटी होनी चाहिए.",
        "error_file": "पहले QR की तस्वीर अपलोड करें।",
        "error_analysis": "QR विश्लेषण विफल हुआ। फिर प्रयास करें।",
        "footer": "TrustCheck · समझदारी से स्कैन करें। सुरक्षित रहें।",
        "disclaimer": "महत्वपूर्ण अनुरोधों की स्वतंत्र रूप से पुष्टि करें। अनजान QR पर आंख बंद करके भरोसा न करें।",
        "scan_date": "स्कैन समय", "type": "प्रकार",
        "checks_limited": "जांच अधूरी",
        "dashboard_empty": "पहले स्कैन के बाद आंकड़े यहां दिखेंगे।",
        "open_scanner": "QR स्कैनर खोलें",
        "no_decoded": "पढ़ी गई जानकारी उपलब्ध नहीं है।",
        "unknown": "अज्ञात",
    },
    "Marathi": {
        "language": "मराठी", "workspace": "कार्य क्षेत्र",
        "dashboard": "डॅशबोर्ड", "scanner": "QR स्कॅनर",
        "platform": "TRUSTCHECK सुरक्षा", "ready": "सिस्टम तयार",
        "overview": "सुरक्षा आढावा",
        "overview_sub": "या डिव्हाइसवर तपासलेल्या QR कोडचा सारांश.",
        "total": "एकूण स्कॅन", "low_count": "कमी धोका",
        "medium_count": "मध्यम धोका", "high_count": "उच्च धोका",
        "distribution": "धोक्याचे वितरण", "qr_types": "तपासलेले QR प्रकार",
        "recent": "अलीकडील स्कॅन", "no_history": "अद्याप स्कॅन इतिहास नाही. डॅशबोर्ड सुरू करण्यासाठी QR कोड तपासा.",
        "scanner_title": "QR सुरक्षा स्कॅनर",
        "scanner_sub": "QR मधील माहिती समजून घेण्यासाठी आणि संभाव्य धोके तपासण्यासाठी प्रतिमा अपलोड करा.",
        "upload_title": "QR प्रतिमा येथे टाका",
        "upload_sub": "तुमच्या डिव्हाइसवरून प्रतिमा निवडा",
        "formats": "PNG, JPG किंवा WEBP · कमाल 5 MB",
        "file": "QR प्रतिमा निवडा", "analyze": "QR कोडचे विश्लेषण करा",
        "loading": "प्रथम स्थानिक पातळीवर QR वाचून तपासत आहे...",
        "remove": "प्रतिमा काढा", "report": "QR विश्लेषण अहवाल",
        "completed": "विश्लेषण पूर्ण", "qr": "QR कोड",
        "risk_heading": "सुरक्षा जोखीम पातळी", "low": "कमी",
        "medium": "मध्यम", "high": "उच्च",
        "inconclusive": "अनिर्णित", "score": "धोका गुण",
        "out_of": "100 पैकी", "low_title": "मोठी धोक्याची चिन्हे आढळली नाहीत",
        "medium_title": "सावधगिरीने पुढे जा",
        "high_title": "गंभीर सुरक्षा इशारा आढळला",
        "inconclusive_title": "तपासणीचा निष्कर्ष स्पष्ट नाही",
        "low_text": "पूर्ण झालेल्या तपासणीत मोठी धोक्याची चिन्हे आढळली नाहीत. ही सुरक्षिततेची हमी नाही.",
        "medium_text": "काही इशारे किंवा अपूर्ण तपासणीकडे लक्ष देणे आवश्यक आहे. पुढे जाण्यापूर्वी तपासा.",
        "high_text": "उपलब्ध माहिती संभाव्य धोका दर्शवते. QR मधील सूचनांचे पालन करू नका.",
        "inconclusive_text": "धोका निश्चित करण्यासाठी पुरेशी माहिती उपलब्ध नाही.",
        "contents": "या QR मध्ये काय आहे?", "purpose": "याचा उपयोग कशासाठी होतो?",
        "happens": "वापरल्यास काय होईल?",
        "destination": "हा QR तुम्हाला कुठे नेतो?",
        "original": "मूळ गंतव्य", "final": "अंतिम गंतव्य",
        "redirect": "रीडायरेक्ट माहिती",
        "not_confirmed": "अंतिम गंतव्याची खात्री करता आली नाही.",
        "no_destination": "या QR साठी वेबसाइटचे गंतव्य आढळले नाही.",
        "why": "ही धोका पातळी का आहे?", "consequences": "काय नुकसान होऊ शकते?",
        "do": "तुम्ही काय करावे?", "avoid": "काय टाळावे?",
        "details": "वाचलेली माहिती", "show": "वाचलेली माहिती पहा",
        "no_findings": "स्थानिक तपासणीत विशिष्ट इशारे आढळले नाहीत. हा QR सुरक्षित असल्याचा पुरावा नाही.",
        "no_info": "अतिरिक्त माहिती उपलब्ध नाही.",
        "safe_action": "कृती करण्यापूर्वी QR चा स्रोत आणि माहिती स्वतंत्रपणे तपासा.",
        "avoid_action": "पासवर्ड, OTP, UPI PIN किंवा बँकिंग माहिती शेअर करू नका. अनोळखी पेमेंट मंजूर करू नका किंवा अज्ञात अॅप इन्स्टॉल करू नका.",
        "incomplete": "काही तपासण्या पूर्ण होऊ शकल्या नाहीत. ही तपासणीची मर्यादा आहे; QR धोकादायक किंवा सुरक्षित असल्याचा पुरावा नाही.",
        "url_warning": "अनोळखी लिंक थेट उघडू नका. वेबसाइटची स्वतंत्रपणे खात्री करा.",
        "safety": "TrustCheck उपलब्ध पुराव्यावर आधारित मार्गदर्शन देते; सुरक्षिततेची हमी देत नाही.",
        "new_scan": "दुसरा QR स्कॅन करा", "no_qr": "या प्रतिमेत QR कोड आढळला नाही.",
        "error_size": "प्रतिमा 5 MB पेक्षा लहान असावी.",
        "error_file": "कृपया आधी QR प्रतिमा अपलोड करा.",
        "error_analysis": "QR विश्लेषण अयशस्वी झाले. पुन्हा प्रयत्न करा.",
        "footer": "TrustCheck · सुरक्षितपणे स्कॅन करा.",
        "disclaimer": "महत्त्वाच्या विनंत्यांची स्वतंत्रपणे खात्री करा. अनोळखी QR वर आंधळेपणाने विश्वास ठेवू नका.",
        "scan_date": "स्कॅन वेळ", "type": "प्रकार",
        "checks_limited": "तपासणी अपूर्ण",
        "dashboard_empty": "पहिल्या स्कॅननंतर आकडेवारी येथे दिसेल.",
        "open_scanner": "QR स्कॅनर उघडा",
        "no_decoded": "वाचलेली माहिती उपलब्ध नाही.",
        "unknown": "अज्ञात",
    },
}


# ============================================================
# DATABASE - only metadata, never decoded QR payload
# ============================================================

DB_PATH = APP_DIR / "trustcheck_history.db"


def initialize_database():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id TEXT PRIMARY KEY,
                scanned_at TEXT NOT NULL,
                qr_type TEXT,
                risk TEXT,
                score INTEGER
            )
        """)
        conn.commit()


def read_history():
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("""
            SELECT id, scanned_at, qr_type, risk, score
            FROM scan_history
            ORDER BY scanned_at DESC
            LIMIT 100
        """).fetchall()
    return [
        {"id": r[0], "scannedAt": r[1], "qrType": r[2], "risk": r[3], "score": r[4]}
        for r in rows
    ]


def save_history(results):
    now = datetime.now().isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        for index, item in enumerate(results):
            risk_obj = item.get("risk_analysis") or {}
            ai_obj = get_ai_object(item)
            unique = hashlib.sha256(
                f"{now}|{item.get('qr_type', 'UNKNOWN')}|{index}".encode()
            ).hexdigest()[:24]
            conn.execute(
                """INSERT OR IGNORE INTO scan_history
                   (id, scanned_at, qr_type, risk, score)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    unique, now, item.get("qr_type", "UNKNOWN"),
                    get_risk_level(risk_obj, ai_obj), get_score(risk_obj),
                ),
            )
        conn.commit()


initialize_database()


# ============================================================
# SESSION STATE
# ============================================================

for key, default in {
    "language": "English",
    "page": "scanner",
    "scan_data": None,
    "uploaded_file_hash": None,
    "error": "",
}.items():
    if key not in st.session_state:
        st.session_state[key] = default


# ============================================================
# HELPERS
# ============================================================

SENSITIVE_KEYS = (
    "password", "passwd", "secret", "token", "otp", "credential",
    "authorization", "auth_key", "pin",
)


def esc(value):
    return html.escape(str(value if value is not None else ""))


def safe_text(value, fallback=""):
    if value is None or value == "":
        return fallback
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return fallback


def format_label(value):
    return str(value or "").replace("_", " ").replace("-", " ").title()


def get_risk_level(risk, ai=None):
    risk = risk if isinstance(risk, dict) else {}
    ai = ai if isinstance(ai, dict) else {}
    value = str(
        risk.get("risk_level") or risk.get("level")
        or ai.get("risk_level") or ""
    ).upper()
    if "HIGH" in value or "MALICIOUS" in value:
        return "HIGH"
    if "MEDIUM" in value or "SUSPICIOUS" in value:
        return "MEDIUM"
    if value in ("LOW", "SAFE"):
        return "LOW"
    return "INCONCLUSIVE"


def get_score(risk):
    risk = risk if isinstance(risk, dict) else {}
    value = risk.get("risk_score")
    if value is None:
        value = risk.get("score", risk.get("risk_rate"))
    try:
        number = float(value)
        return round(number) if 0 <= number <= 100 else None
    except (TypeError, ValueError):
        return None


def safe_details(value, prefix=""):
    output = []
    if not isinstance(value, dict):
        return output
    for key, val in value.items():
        key_text = str(key)
        if any(secret in key_text.lower() for secret in SENSITIVE_KEYS):
            continue
        if val is None or val == "":
            continue
        current = f"{prefix} · {key_text}" if prefix else key_text
        if isinstance(val, dict):
            output.extend(safe_details(val, current))
        elif isinstance(val, list):
            for index, item in enumerate(val, 1):
                if isinstance(item, dict):
                    output.extend(safe_details(item, f"{current} {index}"))
                elif item is not None and item != "":
                    output.append({"key": f"{current} {index}", "value": str(item)})
        elif isinstance(val, (str, int, float, bool)):
            output.append({"key": current, "value": str(val)})
    return output


def find_value(value, keys):
    if not isinstance(value, dict):
        return ""
    for key, val in value.items():
        if str(key).lower() in keys and isinstance(val, str) and val.strip():
            return val
    for val in value.values():
        if isinstance(val, dict):
            found = find_value(val, keys)
            if found:
                return found
    return ""


def get_ai_object(item):
    ai = item.get("ai_analysis") or {}
    if isinstance(ai, dict):
        nested = ai.get("analysis")
        return nested if isinstance(nested, dict) else ai
    return {}


def get_decoded_content(result):
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        for key in ("data", "text", "content", "raw_value", "value", "decoded_text"):
            value = result.get(key)
            if isinstance(value, str) and value:
                return value
    return ""


def risk_label(level, t):
    return t.get(level.lower(), level)


FIELD_LABELS = {
    "English": {"upi_id":"UPI ID", "payee_name":"Recipient / merchant", "amount":"Amount", "currency":"Currency", "transaction_note":"Payment note", "transaction_reference":"Transaction reference", "merchant_code":"Merchant code", "network_name":"Wi-Fi network name", "security_type":"Wi-Fi security", "hidden_network":"Hidden network", "identity":"Network identity", "domain":"Website domain", "scheme":"URL protocol", "path":"URL path", "query_parameters":"URL parameters", "name":"Name", "organisation":"Organisation", "title":"Title", "phone_numbers":"Phone numbers", "emails":"Email addresses", "websites":"Websites", "addresses":"Addresses", "recipient_number":"Recipient number", "message":"Message", "latitude":"Latitude", "longitude":"Longitude", "coordinates_valid":"Valid coordinates", "service":"Service", "phone_number":"Phone number", "prefilled_message":"Pre-filled message", "wallet_or_destination":"Wallet / destination", "payment_parameters":"Payment parameters", "authentication_type":"Authentication type", "account_label":"Account", "issuer":"Issuer", "algorithm":"Algorithm", "digits":"Code digits", "period":"Code period", "text":"Decoded text", "isbn":"ISBN", "product":"Product", "event":"Event", "start":"Start", "end":"End", "location":"Location", "description":"Description", "warning":"Note"},
    "Hindi": {"upi_id":"UPI आईडी", "payee_name":"प्राप्तकर्ता / व्यापारी", "amount":"राशि", "currency":"मुद्रा", "transaction_note":"भुगतान टिप्पणी", "transaction_reference":"लेनदेन संदर्भ", "merchant_code":"व्यापारी कोड", "network_name":"वाई-फाई नेटवर्क नाम", "security_type":"वाई-फाई सुरक्षा", "hidden_network":"छिपा नेटवर्क", "identity":"नेटवर्क पहचान", "domain":"वेबसाइट डोमेन", "scheme":"URL प्रोटोकॉल", "path":"URL पथ", "query_parameters":"URL पैरामीटर", "name":"नाम", "organisation":"संस्था", "title":"पद", "phone_numbers":"फोन नंबर", "emails":"ईमेल पते", "websites":"वेबसाइट", "addresses":"पते", "recipient_number":"प्राप्तकर्ता नंबर", "message":"संदेश", "latitude":"अक्षांश", "longitude":"देशांतर", "coordinates_valid":"मान्य निर्देशांक", "service":"सेवा", "phone_number":"फोन नंबर", "prefilled_message":"पहले से भरा संदेश", "wallet_or_destination":"वॉलेट / गंतव्य", "payment_parameters":"भुगतान पैरामीटर", "authentication_type":"प्रमाणीकरण प्रकार", "account_label":"खाता", "issuer":"जारीकर्ता", "algorithm":"एल्गोरिदम", "digits":"कोड अंक", "period":"कोड अवधि", "text":"पढ़ा गया टेक्स्ट", "isbn":"ISBN", "product":"उत्पाद", "event":"कार्यक्रम", "start":"शुरुआत", "end":"समाप्ति", "location":"स्थान", "description":"विवरण", "warning":"सूचना"},
    "Marathi": {"upi_id":"UPI आयडी", "payee_name":"प्राप्तकर्ता / व्यापारी", "amount":"रक्कम", "currency":"चलन", "transaction_note":"पेमेंट टीप", "transaction_reference":"व्यवहार संदर्भ", "merchant_code":"व्यापारी कोड", "network_name":"वाय-फाय नेटवर्कचे नाव", "security_type":"वाय-फाय सुरक्षा", "hidden_network":"लपवलेले नेटवर्क", "identity":"नेटवर्क ओळख", "domain":"वेबसाइट डोमेन", "scheme":"URL प्रोटोकॉल", "path":"URL पथ", "query_parameters":"URL पॅरामीटर्स", "name":"नाव", "organisation":"संस्था", "title":"पद", "phone_numbers":"फोन क्रमांक", "emails":"ईमेल पत्ते", "websites":"वेबसाइट्स", "addresses":"पत्ते", "recipient_number":"प्राप्तकर्त्याचा क्रमांक", "message":"संदेश", "latitude":"अक्षांश", "longitude":"रेखांश", "coordinates_valid":"वैध निर्देशांक", "service":"सेवा", "phone_number":"फोन क्रमांक", "prefilled_message":"आधी भरलेला संदेश", "wallet_or_destination":"वॉलेट / गंतव्य", "payment_parameters":"पेमेंट पॅरामीटर्स", "authentication_type":"प्रमाणीकरण प्रकार", "account_label":"खाते", "issuer":"जारीकर्ता", "algorithm":"अल्गोरिदम", "digits":"कोड अंक", "period":"कोड कालावधी", "text":"वाचलेला मजकूर", "isbn":"ISBN", "product":"उत्पादन", "event":"कार्यक्रम", "start":"सुरुवात", "end":"समाप्ती", "location":"ठिकाण", "description":"वर्णन", "warning":"सूचना"}
}

QR_COPY = {
 "English": {"URL":"This QR contains a website address. It can open the website shown below.","PAYMENT_URL":"This QR contains a payment-related web link. It may open a payment page; the merchant is not verified by the link alone.","UPI_PAYMENT":"This QR contains UPI payment instructions.","UPI_ID":"This QR contains a UPI payment address. The account holder's identity is not verified by the address alone.","WIFI":"This QR contains Wi-Fi connection settings. A compatible device can use them to join the named network.","CONTACT":"This QR contains a digital contact card. The extracted contact fields are listed below.","EMAIL":"This QR contains an email address or an instruction to compose an email.","EMAIL_ADDRESS":"This QR contains an email address.","SMS":"This QR prepares a text message with the recipient and/or message shown below.","PHONE":"This QR contains a telephone number or call action.","PHONE_NUMBER":"This QR contains a telephone number.","LOCATION":"This QR contains geographic coordinates or a map location.","WHATSAPP_CHAT":"This QR contains a WhatsApp chat link.","WHATSAPP_GROUP":"This QR contains a WhatsApp group invitation link.","CRYPTO_PAYMENT":"This QR contains cryptocurrency wallet or payment information.","AUTHENTICATION":"This QR contains authenticator setup information. Secret values are hidden.","TEXT":"This QR contains plain text. The decoded text is shown below.","PRODUCT":"This QR contains product identification information.","ISBN":"This QR contains an ISBN book identifier.","CALENDAR":"This QR contains calendar event information.","EVENT":"This QR contains event information.","UNKNOWN_URI":"This QR contains a URI in a format that could not be identified confidently.","UNKNOWN":"This QR contains data in an unrecognised format.","fallback":"The QR was decoded, but the available fields do not identify a more specific purpose."},
 "Hindi": {"URL":"इस QR में वेबसाइट का पता है। इसे खोलने पर नीचे दिखाया गया वेब पेज खुल सकता है।","PAYMENT_URL":"इस QR में भुगतान से जुड़ा वेब लिंक है। यह भुगतान पेज खोल सकता है; केवल लिंक से व्यापारी की पुष्टि नहीं होती।","UPI_PAYMENT":"इस QR में UPI भुगतान के निर्देश हैं।","UPI_ID":"इस QR में UPI भुगतान पता है। केवल पते से खाताधारक की पहचान सत्यापित नहीं होती।","WIFI":"इस QR में वाई-फाई से जुड़ने की सेटिंग है। संगत डिवाइस इनकी मदद से बताए गए नेटवर्क से जुड़ सकता है।","CONTACT":"इस QR में डिजिटल संपर्क कार्ड है। निकाली गई संपर्क जानकारी नीचे दी गई है।","EMAIL":"इस QR में ईमेल पता या ईमेल लिखने का निर्देश है।","EMAIL_ADDRESS":"इस QR में ईमेल पता है।","SMS":"इस QR में SMS तैयार करने का निर्देश है। प्राप्तकर्ता और संदेश नीचे दिखाए गए हैं।","PHONE":"इस QR में फोन नंबर या कॉल करने की क्रिया है।","PHONE_NUMBER":"इस QR में फोन नंबर है।","LOCATION":"इस QR में भौगोलिक निर्देशांक या मानचित्र स्थान है।","WHATSAPP_CHAT":"इस QR में WhatsApp चैट लिंक है।","WHATSAPP_GROUP":"इस QR में WhatsApp समूह आमंत्रण लिंक है।","CRYPTO_PAYMENT":"इस QR में क्रिप्टोकरेंसी वॉलेट या भुगतान की जानकारी है।","AUTHENTICATION":"इस QR में ऑथेंटिकेटर सेटअप की जानकारी है। गुप्त मान छिपाए गए हैं।","TEXT":"इस QR में सामान्य टेक्स्ट है। पढ़ा गया टेक्स्ट नीचे दिखाया गया है।","PRODUCT":"इस QR में उत्पाद पहचान की जानकारी है।","ISBN":"इस QR में पुस्तक का ISBN पहचान नंबर है।","CALENDAR":"इस QR में कैलेंडर कार्यक्रम की जानकारी है।","EVENT":"इस QR में कार्यक्रम की जानकारी है।","UNKNOWN_URI":"इस QR में ऐसा URI है जिसका प्रारूप निश्चित रूप से पहचाना नहीं जा सका।","UNKNOWN":"इस QR में ऐसा डेटा है जिसका प्रारूप पहचाना नहीं गया।","fallback":"QR पढ़ लिया गया है, लेकिन उपलब्ध फ़ील्ड से इसका उद्देश्य अधिक स्पष्ट नहीं है।"},
 "Marathi": {"URL":"या QR मध्ये वेबसाइटचा पत्ता आहे. तो उघडल्यास खाली दाखवलेले वेबपेज उघडू शकते.","PAYMENT_URL":"या QR मध्ये पेमेंटशी संबंधित वेब लिंक आहे. ती पेमेंट पेज उघडू शकते; केवळ लिंकवरून व्यापाऱ्याची खात्री होत नाही.","UPI_PAYMENT":"या QR मध्ये UPI पेमेंटच्या सूचना आहेत.","UPI_ID":"या QR मध्ये UPI पेमेंट पत्ता आहे. केवळ पत्त्यावरून खातेदाराची ओळख सत्यापित होत नाही.","WIFI":"या QR मध्ये वाय-फाय जोडणीची सेटिंग्ज आहेत. सुसंगत डिव्हाइस या नेटवर्कशी जोडले जाऊ शकते.","CONTACT":"या QR मध्ये डिजिटल संपर्क कार्ड आहे. मिळालेली संपर्क माहिती खाली दिली आहे.","EMAIL":"या QR मध्ये ईमेल पत्ता किंवा ईमेल तयार करण्याची सूचना आहे.","EMAIL_ADDRESS":"या QR मध्ये ईमेल पत्ता आहे.","SMS":"या QR मध्ये SMS तयार करण्याची सूचना आहे. प्राप्तकर्ता आणि संदेश खाली दाखवले आहेत.","PHONE":"या QR मध्ये फोन क्रमांक किंवा कॉल करण्याची कृती आहे.","PHONE_NUMBER":"या QR मध्ये फोन क्रमांक आहे.","LOCATION":"या QR मध्ये भौगोलिक निर्देशांक किंवा नकाशावरील ठिकाण आहे.","WHATSAPP_CHAT":"या QR मध्ये WhatsApp चॅट लिंक आहे.","WHATSAPP_GROUP":"या QR मध्ये WhatsApp गटाचे आमंत्रण लिंक आहे.","CRYPTO_PAYMENT":"या QR मध्ये क्रिप्टोकरन्सी वॉलेट किंवा पेमेंट माहिती आहे.","AUTHENTICATION":"या QR मध्ये ऑथेंटिकेटर सेटअप माहिती आहे. गुप्त मूल्ये लपवली आहेत.","TEXT":"या QR मध्ये साधा मजकूर आहे. वाचलेला मजकूर खाली दाखवला आहे.","PRODUCT":"या QR मध्ये उत्पादन ओळख माहिती आहे.","ISBN":"या QR मध्ये पुस्तकाचा ISBN ओळख क्रमांक आहे.","CALENDAR":"या QR मध्ये कॅलेंडर कार्यक्रमाची माहिती आहे.","EVENT":"या QR मध्ये कार्यक्रमाची माहिती आहे.","UNKNOWN_URI":"या QR मध्ये असा URI आहे ज्याचा प्रकार खात्रीने ओळखता आला नाही.","UNKNOWN":"या QR मध्ये न ओळखलेल्या स्वरूपातील डेटा आहे.","fallback":"QR वाचला गेला आहे, परंतु उपलब्ध माहितीवरून त्याचा उद्देश अधिक स्पष्ट होत नाही."}
}


# Complete report language fallback for deterministic local findings.
REPORT_TRANSLATIONS = {'Hindi': {'UPI payment destination present': 'QR में UPI भुगतान गंतव्य मौजूद है', 'A UPI ID is encoded in the QR. Its account ownership has not been independently verified.': 'QR में UPI ID दर्ज है। इस ID के खाते के स्वामित्व की स्वतंत्र रूप से पुष्टि नहीं हुई है।', 'Payee name present': 'प्राप्तकर्ता का नाम मौजूद है', 'A payee name is encoded in the QR, but the actual account holder has not been verified.': 'QR में प्राप्तकर्ता का नाम दर्ज है, लेकिन वास्तविक खाताधारक की पुष्टि नहीं हुई है।', 'Payment verification required': 'भुगतान की पुष्टि आवश्यक है', 'Check the recipient name and amount displayed in your trusted UPI application. Never approve an unexpected collect request.': 'अपने विश्वसनीय UPI ऐप में प्राप्तकर्ता का नाम और राशि जांचें। किसी अनपेक्षित कलेक्ट अनुरोध को कभी मंजूर न करें।', 'Payment amount present': 'भुगतान राशि मौजूद है', 'UPI ID not identified': 'UPI ID की पहचान नहीं हुई', 'A payment destination could not be extracted from the available information.': 'उपलब्ध जानकारी से भुगतान गंतव्य प्राप्त नहीं किया जा सका।', 'Unusual payment amount': 'असामान्य भुगतान राशि', 'The encoded payment amount is zero or negative.': 'QR में दर्ज भुगतान राशि शून्य या ऋणात्मक है।', 'Invalid payment amount': 'अमान्य भुगतान राशि', 'The encoded payment amount could not be interpreted reliably.': 'QR में दर्ज भुगतान राशि को विश्वसनीय रूप से समझा नहीं जा सका।', 'Known threat detected': 'ज्ञात खतरे का पता चला', 'An external threat-intelligence service identified this URL on a known threat list. Avoid opening it.': 'बाहरी खतरा-जांच सेवा ने इस URL को ज्ञात खतरों की सूची में पाया है। इसे खोलने से बचें।', 'No known threat match': 'कोई ज्ञात खतरा नहीं मिला', 'The external threat check found no known threat match. This does not guarantee safety.': 'बाहरी जांच में कोई ज्ञात खतरा नहीं मिला। इसका अर्थ सुरक्षा की गारंटी नहीं है।', 'External verification unavailable': 'बाहरी पुष्टि उपलब्ध नहीं', 'The external threat check could not be completed.': 'बाहरी खतरे की जांच पूरी नहीं हो सकी।', 'URL not externally verified': 'URL की बाहरी पुष्टि नहीं हुई', 'No external threat-intelligence result is available for this URL.': 'इस URL के लिए बाहरी खतरा-जांच का परिणाम उपलब्ध नहीं है।', 'Redirect inspection unavailable': 'रीडायरेक्ट जांच उपलब्ध नहीं', "The destination's redirect behavior could not be fully verified.": 'गंतव्य के रीडायरेक्ट व्यवहार की पूरी तरह पुष्टि नहीं हो सकी।', 'Website redirects detected': 'वेबसाइट रीडायरेक्ट पाए गए', 'Wi-Fi connection information': 'वाई-फाई कनेक्शन की जानकारी', 'This QR contains Wi-Fi connection details. Connect only to a network you recognise and trust.': 'इस QR में वाई-फाई कनेक्शन की जानकारी है। केवल पहचाने हुए और भरोसेमंद नेटवर्क से जुड़ें।', 'Contact information detected': 'संपर्क जानकारी मिली', "Verify the person's identity before saving or contacting them.": 'संपर्क सहेजने या बात करने से पहले व्यक्ति की पहचान की पुष्टि करें।', 'Email address detected': 'ईमेल पता मिला', 'Verify the recipient before sending sensitive information.': 'संवेदनशील जानकारी भेजने से पहले प्राप्तकर्ता की पुष्टि करें।', 'Phone number detected': 'फोन नंबर मिला', 'Verify the number before calling.': 'कॉल करने से पहले नंबर की पुष्टि करें।', 'Cryptocurrency payment information': 'क्रिप्टोकरेंसी भुगतान की जानकारी', 'Sensitive authentication information': 'संवेदनशील प्रमाणीकरण जानकारी', 'Location information detected': 'स्थान की जानकारी मिली', 'WhatsApp destination detected': 'WhatsApp गंतव्य मिला', 'Unrecognised URI scheme': 'अपरिचित URI स्कीम', 'Calendar or event information': 'कैलेंडर या कार्यक्रम की जानकारी', 'Product identification information': 'उत्पाद पहचान की जानकारी', 'Unsupported URL scheme': 'असमर्थित URL स्कीम', 'Invalid website address': 'अमान्य वेबसाइट पता', 'Embedded URL credentials': 'URL में लॉगिन जानकारी शामिल है', 'Non-standard website port': 'गैर-मानक वेबसाइट पोर्ट', 'Invalid URL port': 'अमान्य URL पोर्ट', 'Website does not use HTTPS': 'वेबसाइट HTTPS का उपयोग नहीं करती', 'IP address used as website': 'वेबसाइट के रूप में IP पता उपयोग हुआ', 'Shortened URL': 'छोटा किया गया URL', 'Encoded international domain': 'एन्कोड किया गया अंतरराष्ट्रीय डोमेन', 'Sensitive-action keywords': 'संवेदनशील कार्रवाई से जुड़े शब्द', 'Unusually complex domain': 'असामान्य रूप से जटिल डोमेन', 'URL parsing failed': 'URL पढ़ने में विफलता', 'Potential scam language': 'संभावित धोखाधड़ी वाली भाषा'}, 'Marathi': {'UPI payment destination present': 'QR मध्ये UPI पेमेंटचा गंतव्य पत्ता आहे', 'A UPI ID is encoded in the QR. Its account ownership has not been independently verified.': 'QR मध्ये UPI ID समाविष्ट आहे. त्या ID च्या खात्याच्या मालकीची स्वतंत्रपणे पडताळणी झालेली नाही.', 'Payee name present': 'पैसे प्राप्त करणाऱ्याचे नाव उपलब्ध आहे', 'A payee name is encoded in the QR, but the actual account holder has not been verified.': 'QR मध्ये प्राप्तकर्त्याचे नाव आहे; परंतु प्रत्यक्ष खातेदाराची पडताळणी झालेली नाही.', 'Payment verification required': 'पेमेंटची पडताळणी आवश्यक आहे', 'Check the recipient name and amount displayed in your trusted UPI application. Never approve an unexpected collect request.': 'तुमच्या विश्वासार्ह UPI अॅपमध्ये प्राप्तकर्त्याचे नाव आणि रक्कम तपासा. अनपेक्षित कलेक्ट विनंती कधीही मंजूर करू नका.', 'Payment amount present': 'पेमेंटची रक्कम उपलब्ध आहे', 'UPI ID not identified': 'UPI ID ओळखता आली नाही', 'A payment destination could not be extracted from the available information.': 'उपलब्ध माहितीमधून पेमेंटचा गंतव्य पत्ता मिळवता आला नाही.', 'Unusual payment amount': 'असामान्य पेमेंट रक्कम', 'The encoded payment amount is zero or negative.': 'QR मध्ये नोंदवलेली पेमेंट रक्कम शून्य किंवा ऋण आहे.', 'Invalid payment amount': 'अवैध पेमेंट रक्कम', 'The encoded payment amount could not be interpreted reliably.': 'QR मधील पेमेंट रक्कम विश्वसनीयपणे समजली नाही.', 'Known threat detected': 'ज्ञात धोका आढळला', 'An external threat-intelligence service identified this URL on a known threat list. Avoid opening it.': 'बाह्य धोका-माहिती सेवेला हा URL ज्ञात धोक्यांच्या यादीत आढळला. तो उघडू नका.', 'No known threat match': 'ज्ञात धोका आढळला नाही', 'The external threat check found no known threat match. This does not guarantee safety.': 'बाह्य तपासणीत ज्ञात धोका आढळला नाही. याचा अर्थ सुरक्षिततेची हमी नाही.', 'External verification unavailable': 'बाह्य पडताळणी उपलब्ध नाही', 'The external threat check could not be completed.': 'बाह्य धोका तपासणी पूर्ण करता आली नाही.', 'URL not externally verified': 'URL ची बाह्य पडताळणी झालेली नाही', 'No external threat-intelligence result is available for this URL.': 'या URL साठी बाह्य धोका तपासणीचा निकाल उपलब्ध नाही.', 'Redirect inspection unavailable': 'रीडायरेक्ट तपासणी उपलब्ध नाही', "The destination's redirect behavior could not be fully verified.": 'गंतव्याच्या रीडायरेक्ट वर्तनाची पूर्ण पडताळणी करता आली नाही.', 'Website redirects detected': 'वेबसाइट रीडायरेक्ट आढळले', 'Wi-Fi connection information': 'वाय-फाय कनेक्शनची माहिती', 'This QR contains Wi-Fi connection details. Connect only to a network you recognise and trust.': 'या QR मध्ये वाय-फाय कनेक्शनची माहिती आहे. फक्त ओळखीच्या आणि विश्वासार्ह नेटवर्कशी जोडा.', 'Contact information detected': 'संपर्काची माहिती आढळली', "Verify the person's identity before saving or contacting them.": 'संपर्क जतन करण्यापूर्वी किंवा संपर्क साधण्यापूर्वी व्यक्तीची ओळख तपासा.', 'Email address detected': 'ईमेल पत्ता आढळला', 'Verify the recipient before sending sensitive information.': 'संवेदनशील माहिती पाठवण्यापूर्वी प्राप्तकर्त्याची खात्री करा.', 'Phone number detected': 'फोन क्रमांक आढळला', 'Verify the number before calling.': 'फोन करण्यापूर्वी क्रमांक तपासा.', 'Cryptocurrency payment information': 'क्रिप्टोकरन्सी पेमेंटची माहिती', 'Sensitive authentication information': 'संवेदनशील प्रमाणीकरण माहिती', 'Location information detected': 'स्थानाची माहिती आढळली', 'WhatsApp destination detected': 'WhatsApp गंतव्य आढळले', 'Unrecognised URI scheme': 'अनोळखी URI स्कीम', 'Calendar or event information': 'दिनदर्शिका किंवा कार्यक्रमाची माहिती', 'Product identification information': 'उत्पादन ओळख माहिती', 'Unsupported URL scheme': 'असमर्थित URL स्कीम', 'Invalid website address': 'अवैध वेबसाइट पत्ता', 'Embedded URL credentials': 'URL मध्ये लॉगिन माहिती समाविष्ट आहे', 'Non-standard website port': 'अप्रमाणित वेबसाइट पोर्ट', 'Invalid URL port': 'अवैध URL पोर्ट', 'Website does not use HTTPS': 'वेबसाइट HTTPS वापरत नाही', 'IP address used as website': 'वेबसाइटसाठी IP पत्ता वापरला आहे', 'Shortened URL': 'लहान केलेला URL', 'Encoded international domain': 'एन्कोड केलेले आंतरराष्ट्रीय डोमेन', 'Sensitive-action keywords': 'संवेदनशील कृती दर्शवणारे शब्द', 'Unusually complex domain': 'असामान्यपणे गुंतागुंतीचे डोमेन', 'URL parsing failed': 'URL वाचता आला नाही', 'Potential scam language': 'संभाव्य फसवणुकीची भाषा'}}
def translate_report_text(value, language):
    if not isinstance(value, str) or language == 'English': return value
    return REPORT_TRANSLATIONS.get(language, {}).get(value, value)
def localized_severity(value, language):
    labels={'Hindi': {'HIGH':'उच्च','MEDIUM':'मध्यम','LOW':'कम','INFO':'जानकारी','UNKNOWN':'अज्ञात'}, 'Marathi': {'HIGH':'उच्च','MEDIUM':'मध्यम','LOW':'कमी','INFO':'माहिती','UNKNOWN':'अज्ञात'}}
    return labels.get(language, {}).get(str(value).upper(), format_label(value))

def localized_field_label(key, language):
    raw = str(key).split(" · ")[-1].lower()
    # Array entries such as phone_numbers 1 keep the same translated field name.
    tail = raw.rsplit(" ", 1)
    if len(tail) == 2 and tail[1].isdigit():
        raw = tail[0]
    return FIELD_LABELS.get(language, FIELD_LABELS["English"]).get(raw, format_label(raw))

QR_TYPE_LABELS = {
    "Hindi": {"URL":"वेबसाइट लिंक", "PAYMENT_URL":"भुगतान लिंक", "UPI_PAYMENT":"UPI भुगतान", "UPI_ID":"UPI पता", "WIFI":"वाई-फाई नेटवर्क", "CONTACT":"संपर्क कार्ड", "EMAIL":"ईमेल निर्देश", "EMAIL_ADDRESS":"ईमेल पता", "SMS":"SMS संदेश", "PHONE":"फोन कॉल", "PHONE_NUMBER":"फोन नंबर", "LOCATION":"स्थान", "WHATSAPP_CHAT":"WhatsApp चैट", "WHATSAPP_GROUP":"WhatsApp समूह आमंत्रण", "CRYPTO_PAYMENT":"क्रिप्टो भुगतान", "AUTHENTICATION":"प्रमाणीकरण सेटअप", "TEXT":"साधारण टेक्स्ट", "PRODUCT":"उत्पाद कोड", "ISBN":"ISBN पुस्तक कोड", "CALENDAR":"कैलेंडर कार्यक्रम", "EVENT":"कार्यक्रम", "UNKNOWN_URI":"अज्ञात URI", "UNKNOWN":"अज्ञात QR डेटा"},
    "Marathi": {"URL":"वेबसाइट लिंक", "PAYMENT_URL":"पेमेंट लिंक", "UPI_PAYMENT":"UPI पेमेंट", "UPI_ID":"UPI पत्ता", "WIFI":"वाय-फाय नेटवर्क", "CONTACT":"संपर्क कार्ड", "EMAIL":"ईमेल सूचना", "EMAIL_ADDRESS":"ईमेल पत्ता", "SMS":"SMS संदेश", "PHONE":"फोन कॉल", "PHONE_NUMBER":"फोन क्रमांक", "LOCATION":"ठिकाण", "WHATSAPP_CHAT":"WhatsApp चॅट", "WHATSAPP_GROUP":"WhatsApp गट आमंत्रण", "CRYPTO_PAYMENT":"क्रिप्टो पेमेंट", "AUTHENTICATION":"प्रमाणीकरण सेटअप", "TEXT":"साधा मजकूर", "PRODUCT":"उत्पादन कोड", "ISBN":"ISBN पुस्तक कोड", "CALENDAR":"कॅलेंडर कार्यक्रम", "EVENT":"कार्यक्रम", "UNKNOWN_URI":"अज्ञात URI", "UNKNOWN":"अज्ञात QR डेटा"}
}

def localized_qr_type(qr_type, language):
    kind = str(qr_type or "UNKNOWN").upper()
    return QR_TYPE_LABELS.get(language, {}).get(kind, format_label(kind))

def flatten_safe_details(value, prefix=""):
    rows = []
    if isinstance(value, dict):
        for key, val in value.items():
            low = str(key).lower()
            if any(secret in low for secret in SENSITIVE_KEYS) or val is None or val == "":
                continue
            label = f"{prefix} · {key}" if prefix else str(key)
            if isinstance(val, (dict, list)):
                rows.extend(flatten_safe_details(val, label))
            else:
                rows.append({"key": label, "value": str(val)})
    elif isinstance(value, list):
        for i, val in enumerate(value, 1):
            rows.extend(flatten_safe_details(val, f"{prefix} {i}"))
    return rows

def build_localized_qr_summary(qr_type, details, language):
    kind = str(qr_type or "UNKNOWN").upper()
    base = QR_COPY.get(language, QR_COPY["English"]).get(kind, QR_COPY.get(language, QR_COPY["English"])["fallback"])
    # Add concrete extracted values; never infer values that the parser did not return.
    rows = flatten_safe_details(details)
    vals = {str(r["key"]).split(" · ")[-1].lower(): r["value"] for r in rows}
    extras = []
    if kind in {"UPI_PAYMENT", "UPI", "UPI_ID"}:
        for key in ("payee_name", "upi_id", "amount", "currency", "transaction_note"):
            if vals.get(key): extras.append(f"{localized_field_label(key, language)}: {vals[key]}")
    elif kind == "WIFI":
        for key in ("network_name", "security_type", "hidden_network"):
            if vals.get(key): extras.append(f"{localized_field_label(key, language)}: {vals[key]}")
    elif kind in {"URL", "PAYMENT_URL", "UNKNOWN_URI"}:
        for key in ("domain", "scheme", "path"):
            if vals.get(key): extras.append(f"{localized_field_label(key, language)}: {vals[key]}")
    elif kind in {"CONTACT", "EMAIL", "EMAIL_ADDRESS", "SMS", "PHONE", "PHONE_NUMBER", "LOCATION", "WHATSAPP_CHAT", "WHATSAPP_GROUP", "CRYPTO_PAYMENT", "AUTHENTICATION", "PRODUCT", "ISBN", "CALENDAR", "EVENT"}:
        for row in rows:
            extras.append(f"{localized_field_label(row['key'], language)}: {row['value']}")
    if language == "Hindi":
        intro = "निकाली गई जानकारी:"
    elif language == "Marathi":
        intro = "मिळालेली माहिती:"
    else:
        intro = "Extracted information:"
    return base + (("\n\n" + intro + "\n" + "\n".join("• " + x for x in extras)) if extras else "")


# ============================================================
# VISUAL DESIGN - dark navy / cyan / blue, React-inspired
# ============================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

:root {
  --bg:#091421; --sidebar:#0b1929; --panel:#122238; --panel2:#172d45;
  --cyan:#54dce9; --blue:#65aaff; --green:#35d6a0; --yellow:#f5bd58;
  --red:#ff697b; --text:#edf4fc; --muted:#91a5ba;
  --border:rgba(157,190,220,.14);
}
html, body, [data-testid="stAppViewContainer"] {
  background:var(--bg)!important; color:var(--text)!important;
  font-family:'DM Sans',sans-serif!important;
}
[data-testid="stHeader"] {background:transparent!important;}
[data-testid="stToolbar"] {visibility:hidden;}
[data-testid="stSidebar"] {
  background:var(--sidebar)!important; border-right:1px solid var(--border);
}
[data-testid="stSidebar"] > div:first-child {padding-top:1.25rem;}
.block-container {max-width:1480px;padding:1.7rem 2.5rem 1.5rem;}
h1,h2,h3,h4,strong {font-family:'Plus Jakarta Sans',sans-serif!important;color:var(--text)!important;}
p,span,label,li {color:var(--muted);}
.brand {display:flex;align-items:center;gap:12px;padding:10px 8px 28px;}
.brand-symbol {
  width:48px;height:48px;border-radius:15px;
  background:linear-gradient(135deg,#1c9fb9,#416fe0);
  display:flex;align-items:center;justify-content:center;
  color:white;font-size:25px;box-shadow:0 8px 25px rgba(47,176,217,.2);
}
.brand-name {color:#fff;font-size:21px;font-weight:800;letter-spacing:-.7px;}
.brand-sub {font-size:10px;letter-spacing:2px;color:var(--cyan);display:block;margin-top:2px;}
.eyebrow,.sidebar-label {
  color:var(--cyan)!important;font-size:10px!important;font-weight:800!important;
  letter-spacing:1.7px!important;
}
.sidebar-label {padding:8px 12px;}
.topline {
  display:flex;align-items:center;justify-content:space-between;
  border-bottom:1px solid var(--border);padding-bottom:17px;margin-bottom:26px;
}
.page-title {font-size:32px;font-weight:800;letter-spacing:-1.2px;margin:5px 0;}
.page-subtitle {color:var(--muted);font-size:14px;margin-bottom:24px;line-height:1.65;}
.panel,.stat-card,.upload-panel,.report-card {
  background:linear-gradient(145deg,#14283f,#101f33);
  border:1px solid var(--border);border-radius:17px;
  box-shadow:0 12px 35px rgba(0,0,0,.13);
}
.panel {padding:23px;margin-bottom:20px;}
.panel-title {color:white;font-size:18px;font-weight:750;margin:4px 0 20px;}
.stat-card {padding:21px;min-height:135px;transition:transform .2s,border-color .2s;}
.stat-card:hover,.panel:hover {transform:translateY(-2px);border-color:rgba(84,220,233,.35);}
.stat-label {color:var(--muted);font-size:13px;font-weight:600;}
.stat-value {font-size:34px;font-weight:800;color:white;margin-top:12px;}
.stat-icon {font-size:21px;margin-bottom:12px;}
.upload-panel {padding:26px;margin-bottom:25px;}
.upload-zone {
  border:1.5px dashed rgba(84,220,233,.42);border-radius:16px;
  background:rgba(84,220,233,.035);padding:30px 18px;text-align:center;margin:20px 0;
}
.upload-zone h3 {margin:10px 0 5px;font-size:18px;}
.upload-icon {font-size:38px;color:var(--cyan);}
div.stButton>button {
  background:linear-gradient(100deg,#168eae,#416fe0)!important;color:white!important;
  border:0!important;border-radius:10px!important;padding:10px 18px!important;
  font-weight:750!important;transition:all .2s ease!important;
}
div.stButton>button:hover {filter:brightness(1.13);transform:translateY(-1px);box-shadow:0 8px 20px rgba(41,150,210,.2);}
div.stButton>button:disabled {opacity:.45;}
div[data-testid="stFileUploader"] {
  background:rgba(84,220,233,.025);border:1px dashed rgba(84,220,233,.25);
  border-radius:13px;padding:12px;
}
div[data-testid="stFileUploader"] section {background:transparent!important;}
div[data-testid="stFileUploader"] button {color:var(--cyan)!important;border-color:var(--cyan)!important;}
/* Language dropdown: keep selected value, placeholder and menu options readable */
div[data-testid="stSelectbox"] [data-baseweb="select"] > div {
  background:#152b42!important;
  color:#f4f8ff!important;
  border-color:var(--border)!important;
}
div[data-testid="stSelectbox"] [data-baseweb="select"] *,
div[data-testid="stSelectbox"] [data-baseweb="select"] input,
div[data-testid="stSelectbox"] [data-baseweb="select"] span,
div[data-testid="stSelectbox"] [data-baseweb="select"] div {
  color:#f4f8ff!important;
  -webkit-text-fill-color:#f4f8ff!important;
}
div[data-baseweb="popover"] [role="listbox"],
div[data-baseweb="popover"] [role="option"] {
  background:#152b42!important;
  color:#f4f8ff!important;
}
div[data-baseweb="popover"] [role="option"] * {
  color:#f4f8ff!important;
  -webkit-text-fill-color:#f4f8ff!important;
}
div[data-baseweb="popover"] [role="option"][aria-selected="true"] {
  background:#245071!important;
}
.risk-badge {
  display:inline-block;padding:7px 13px;border-radius:30px;
  font-size:11px;font-weight:850;letter-spacing:1px;white-space:nowrap;
}
.risk-low {color:var(--green)!important;background:rgba(53,214,160,.12);border:1px solid rgba(53,214,160,.25);}
.risk-medium {color:var(--yellow)!important;background:rgba(245,189,88,.12);border:1px solid rgba(245,189,88,.25);}
.risk-high {color:var(--red)!important;background:rgba(255,105,123,.12);border:1px solid rgba(255,105,123,.25);}
.risk-inconclusive {color:#b4c2d2!important;background:rgba(180,194,210,.1);border:1px solid rgba(180,194,210,.25);}
.report-card {padding:24px;margin:0 0 23px;overflow:hidden;}
.report-top {display:flex;justify-content:space-between;align-items:flex-start;gap:20px;margin-bottom:5px;}
.report-top h2 {margin:7px 0;font-size:23px;}
.report-top p {line-height:1.65;font-size:13px;margin-bottom:0;}
.risk-first-card {
  box-sizing:border-box;width:100%;padding:22px 25px;border-radius:16px;
  margin:18px 0 22px;display:flex;align-items:center;justify-content:space-between;
  gap:20px;background:linear-gradient(120deg,#172d45,#102239);
  border:1px solid rgba(157,190,220,.18);box-shadow:0 12px 30px rgba(0,0,0,.16);
}
.risk-first-card h3 {color:var(--text)!important;font-size:20px!important;margin:8px 0!important;}
.risk-first-card p {color:#aebfd1!important;font-size:13px;line-height:1.65;margin:0;}
.risk-number {font-size:35px;font-weight:850;line-height:1.2;}
.risk-first-card.low {border-left:5px solid var(--green);}
.risk-first-card.medium {border-left:5px solid var(--yellow);}
.risk-first-card.high {border-left:5px solid var(--red);}
.risk-first-card.inconclusive {border-left:5px solid #91a5ba;}
.risk-first-card.low .risk-number {color:var(--green);}
.risk-first-card.medium .risk-number {color:var(--yellow);}
.risk-first-card.high .risk-number {color:var(--red);}
.risk-first-card.inconclusive .risk-number {color:#b4c2d2;}
div[data-testid="stHorizontalBlock"] {gap:18px!important;align-items:stretch;}
div[data-testid="stVerticalBlockBorderWrapper"] {
  background:linear-gradient(145deg,#14283f,#101f33)!important;
  border:1px solid rgba(157,190,220,.17)!important;border-radius:15px!important;
  padding:15px 17px!important;box-shadow:0 9px 25px rgba(0,0,0,.13);
  margin-bottom:14px;min-height:145px;
}
div[data-testid="stVerticalBlockBorderWrapper"] h4 {
  color:#edf4fc!important;font-size:14px!important;margin-bottom:12px!important;
}
div[data-testid="stVerticalBlockBorderWrapper"] p,
div[data-testid="stVerticalBlockBorderWrapper"] li {
  color:#bdcddd!important;font-size:13px!important;line-height:1.7!important;
}
.report-section {
  background:rgba(255,255,255,.018);border:1px solid var(--border);
  border-radius:12px;padding:17px;margin-bottom:13px;min-height:120px;
}
.decoded-row,.history-row,.type-row {
  display:flex;justify-content:space-between;gap:15px;padding:11px 0;
  border-bottom:1px solid var(--border);font-size:12px;
}
.decoded-row strong {text-align:right;overflow-wrap:anywhere;max-width:65%;}
.risk-row {margin:18px 0;}
.risk-row-top {display:flex;justify-content:space-between;margin-bottom:9px;font-size:13px;}
.progress {height:8px;border-radius:20px;background:#26384d;overflow:hidden;}
.progress-fill {height:100%;border-radius:20px;}
.empty-state {color:var(--muted);padding:18px 0;font-size:13px;line-height:1.7;}
.notice {
  background:rgba(245,189,88,.08);border:1px solid rgba(245,189,88,.2);
  border-radius:11px;padding:13px 16px;margin:14px 0;color:var(--yellow);
  font-size:13px;line-height:1.7;
}
.report-disclaimer {border-top:1px solid var(--border);margin-top:18px;padding-top:15px;font-size:12px;}
.footer {border-top:1px solid var(--border);padding:18px 0;margin-top:42px;color:var(--muted);font-size:12px;}
.footer strong {color:var(--cyan)!important;}
[data-testid="stExpander"] {background:rgba(84,220,233,.025);border:1px solid var(--border);border-radius:11px;}
[data-testid="stExpander"] summary {color:var(--cyan)!important;}
[data-testid="stImage"] img {border-radius:12px;}
hr {border-color:var(--border)!important;}
@media(max-width:900px) {
  .block-container {padding:1.2rem 1rem;}
  .page-title {font-size:25px;}
  .report-top {flex-direction:column;}
  .risk-first-card {align-items:flex-start;flex-direction:column;}
}
@media(prefers-reduced-motion:reduce) {*{transition:none!important;animation:none!important;}}
</style>
""", unsafe_allow_html=True)


# ============================================================
# CURRENT LANGUAGE + SIDEBAR
# ============================================================

t = COPY[st.session_state.language]

with st.sidebar:
    st.markdown("""
    <div class="brand">
      <div class="brand-symbol">🛡</div>
      <div><div class="brand-name">TrustCheck</div>
      <span class="brand-sub">QR SECURITY</span></div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown(f'<div class="sidebar-label">{t["workspace"]}</div>', unsafe_allow_html=True)

    if st.button(f"▦  {t['dashboard']}", use_container_width=True, key="nav_dashboard"):
        st.session_state.page = "dashboard"
        st.rerun()
    if st.button(f"⌗  {t['scanner']}", use_container_width=True, key="nav_scanner"):
        st.session_state.page = "scanner"
        st.rerun()

    st.markdown("---")
    st.markdown(
        f'<div style="font-size:11px;color:#35d6a0;padding:8px 4px;">● {t["ready"]}</div>',
        unsafe_allow_html=True,
    )

    selected_language = st.selectbox(
        "🌐 Language", list(COPY.keys()),
        index=list(COPY.keys()).index(st.session_state.language),
        format_func=lambda value: COPY[value]["language"],
        key="language_select",
    )
    if selected_language != st.session_state.language:
        st.session_state.language = selected_language
        st.session_state.error = ""
        st.rerun()

t = COPY[st.session_state.language]
page_label = t["dashboard"] if st.session_state.page == "dashboard" else t["scanner"]
st.markdown(f"""
<div class="topline">
  <div><div class="eyebrow">{t["platform"]}</div>
  <div style="font-size:16px;font-weight:800;color:#edf4fc;margin-top:5px;">{page_label}</div></div>
  <div style="font-size:10px;color:#35d6a0;font-weight:800;letter-spacing:1px;">● {t["ready"]}</div>
</div>
""", unsafe_allow_html=True)


# ============================================================
# REPORT RENDERING
# ============================================================

def render_report(item, index):
    risk = item.get("risk_analysis") or {}
    ai = get_ai_object(item)
    level = get_risk_level(risk, ai)
    score = get_score(risk)
    qr_type = safe_text(item.get("qr_type"), "QR_CODE")
    details_obj = item.get("details") or {}
    details = safe_details(details_obj)

    is_url = any(word in qr_type.upper() for word in ("URL", "LINK", "WEB", "WHATSAPP"))
    redirect = item.get("redirect_analysis") or {}
    original = find_value(details_obj, {"url", "original_url", "source_url", "original"})
    if not original:
        original = find_value(redirect, {"original_url", "original", "source_url"})
    final_url = find_value(
        redirect, {"final_url", "final_destination", "destination_url", "final_url_after_redirect"}
    )

    redirect_status = str(redirect.get("status", "")).upper()
    external = item.get("external_security_check") or {}
    external_status = str(external.get("status", "")).upper()
    incomplete = (
        redirect_status in {"INCONCLUSIVE", "NOT_CHECKED", "ERROR", "TIMEOUT", "UNAVAILABLE"}
        or external_status in {"INCONCLUSIVE", "NOT_CHECKED", "ERROR", "TIMEOUT", "UNAVAILABLE"}
    )

    language = st.session_state.language
    localized_summary = build_localized_qr_summary(qr_type, details_obj, language)
    # Prefer a specific local, parser-grounded summary over generic English fallback text.
    description = localized_summary
    ai_language = str(ai.get("language") or "").strip().lower()
    ai_text_matches_language = language == "English" or ai_language == language.lower()
    purpose = safe_text(ai.get("purpose"), "") if ai_text_matches_language else ""
    if not purpose:
        purpose = localized_summary if language != "English" else safe_text(item.get("purpose"), t["no_info"])
    findings = ai.get("findings") if isinstance(ai.get("findings"), list) and ai_text_matches_language else []
    if not findings:
        findings = risk.get("findings") if isinstance(risk.get("findings"), list) else []

    consequence = safe_text(
        (ai.get("possible_consequences") or ai.get("consequences")
        or ai.get("what_could_happen") or ai.get("explanation")) if ai_text_matches_language else None,
        t["no_info"],
    )
    action = safe_text(
        (ai.get("recommendation") or ai.get("what_to_do")
        or ai.get("user_action") or item.get("recommended_action")) if ai_text_matches_language else None,
        t["safe_action"],
    )
    avoid = safe_text(
        (ai.get("what_to_avoid") or ai.get("avoid") or ai.get("precautions")) if ai_text_matches_language else None,
        t["avoid_action"],
    )
    verification_steps = (ai.get("verification_steps") or []) if ai_text_matches_language else []
    limitations = (ai.get("limitations") or []) if ai_text_matches_language else []

    titles = {
        "LOW": t["low_title"], "MEDIUM": t["medium_title"],
        "HIGH": t["high_title"], "INCONCLUSIVE": t["inconclusive_title"],
    }
    summaries = {
        "LOW": t["low_text"], "MEDIUM": t["medium_text"],
        "HIGH": t["high_text"], "INCONCLUSIVE": t["inconclusive_text"],
    }
    badge = risk_label(level, t)
    css_level = level.lower()

    st.markdown(f"""
    <div class="report-card">
      <div class="report-top">
        <div>
          <div class="eyebrow">{t["qr"]} {index + 1} · {t["completed"]}</div>
          <h2>{esc(localized_qr_type(qr_type, language))}</h2>
          <p>{esc(description)}</p>
        </div>
        <div><span class="risk-badge risk-{css_level}">{esc(badge)}</span></div>
      </div>
      <div class="risk-first-card {css_level}">
        <div>
          <div class="eyebrow">{t["risk_heading"]}</div>
          <h3>{esc(titles[level])}</h3>
          <p>{esc(summaries[level])}</p>
        </div>
        <div style="text-align:center;min-width:105px;">
          <div class="risk-number">{score if score is not None else "—"}</div>
          <div style="font-size:11px;color:#91a5ba;margin-top:5px;">{t["score"]} · {t["out_of"]}</div>
          <div style="margin-top:10px;"><span class="risk-badge risk-{css_level}">{esc(badge)}</span></div>
        </div>
      </div>
    """, unsafe_allow_html=True)

    if incomplete:
        st.markdown(f'<div class="notice">ⓘ {t["incomplete"]}</div>', unsafe_allow_html=True)

    left, right = st.columns(2, gap="large")

    with left:
        with st.container(border=True):
            st.markdown(f"#### ◈ {t['contents']}")
            st.write(description)
            if details:
                with st.expander(t["show"]):
                    for detail in details:
                        st.markdown(
                            f'<div class="decoded-row"><span>{esc(localized_field_label(detail["key"], language))}</span>'
                            f'<strong>{esc(detail["value"])}</strong></div>',
                            unsafe_allow_html=True,
                        )
            else:
                st.caption(t["no_decoded"])
            decoded_payload = safe_text(item.get("decoded_content"), "")
            if decoded_payload:
                payload_title = {"English":"Decoded QR payload (sensitive values masked)", "Hindi":"QR से पढ़ा गया डेटा (संवेदनशील मान छिपाए गए)", "Marathi":"QR मधून वाचलेला डेटा (संवेदनशील मूल्ये लपवली आहेत)"}.get(language, "Decoded QR payload")
                with st.expander(payload_title):
                    st.code(decoded_payload[:5000], language=None)

        with st.container(border=True):
            st.markdown(f"#### ◉ {t['happens']}")
            st.write(safe_text((ai.get("what_happens") or ai.get("usage_explanation")) if ai_text_matches_language else None, purpose))

        with st.container(border=True):
            st.markdown(f"#### ⛨ {t['why']}")
            if findings:
                for finding in findings:
                    if isinstance(finding, str):
                        st.markdown(f"- {esc(translate_report_text(finding, language))}")
                    elif isinstance(finding, dict):
                        title = safe_text(
                            finding.get("title") or finding.get("message") or finding.get("type"),
                            t["why"],
                        )
                        title = translate_report_text(title, language)
                        st.markdown(f"**{esc(title)}**")
                        explanation = safe_text(finding.get("explanation") or finding.get("description"))
                        if explanation:
                            st.write(translate_report_text(explanation, language))
                        if finding.get("severity"):
                            st.caption(localized_severity(finding["severity"], language))
            else:
                st.write(safe_text(ai.get("explanation"), t["no_findings"]) if ai_text_matches_language else t["no_findings"])

        with st.container(border=True):
            st.markdown(f"#### ✓ {t['do']}")
            st.write(translate_report_text(action, language))
            if isinstance(verification_steps, list):
                for step in verification_steps:
                    st.markdown(f"- {safe_text(step)}")

    with right:
        with st.container(border=True):
            st.markdown(f"#### ◈ {t['purpose']}")
            st.write(purpose)

        with st.container(border=True):
            st.markdown(f"#### ↗ {t['destination']}")
            if is_url:
                st.caption(t["original"])
                st.write(original or t["not_confirmed"])
                st.caption(t["final"])
                st.write(final_url or t["not_confirmed"])
                st.caption(format_label(redirect_status) if redirect_status else t["checks_limited"])
                st.warning(t["url_warning"])
            else:
                st.write(t["no_destination"])

        with st.container(border=True):
            st.markdown(f"#### ⚠ {t['consequences']}")
            st.write(translate_report_text(consequence, language))

        with st.container(border=True):
            st.markdown(f"#### ✕ {t['avoid']}")
            st.write(translate_report_text(avoid, language))

        if limitations:
            with st.container(border=True):
                st.markdown(f"#### ⓘ {t['checks_limited']}")
                if isinstance(limitations, list):
                    for limitation in limitations:
                        st.markdown(f"- {safe_text(limitation)}")
                else:
                    st.write(safe_text(limitations))

    st.markdown(f'<div class="report-disclaimer">🔒 {t["safety"]}</div></div>', unsafe_allow_html=True)


# ============================================================
# DASHBOARD
# ============================================================

def render_dashboard():
    history = read_history()
    total = len(history)
    low = sum(x["risk"] == "LOW" for x in history)
    medium = sum(x["risk"] == "MEDIUM" for x in history)
    high = sum(x["risk"] == "HIGH" for x in history)
    inconclusive = sum(x["risk"] == "INCONCLUSIVE" for x in history)

    st.markdown(
        f'<div class="eyebrow">{t["platform"]}</div>'
        f'<div class="page-title">{t["overview"]}</div>'
        f'<div class="page-subtitle">{t["overview_sub"]}</div>',
        unsafe_allow_html=True,
    )
    if st.button(f"⌗  {t['open_scanner'] if 'open_scanner' in t else t['scanner']}"):
        st.session_state.page = "scanner"
        st.rerun()

    stats = [
        ("◉", t["total"], total, "#65aaff"),
        ("🛡", t["low_count"], low, "#35d6a0"),
        ("⚠", t["medium_count"], medium, "#f5bd58"),
        ("⛨", t["high_count"], high, "#ff697b"),
    ]
    cols = st.columns(4)
    for col, (icon, label, value, color) in zip(cols, stats):
        with col:
            st.markdown(
                f'<div class="stat-card"><div class="stat-icon" style="color:{color}">{icon}</div>'
                f'<div class="stat-label">{label}</div><div class="stat-value">{value}</div></div>',
                unsafe_allow_html=True,
            )

    st.write("")
    left, right = st.columns(2, gap="large")
    with left:
        st.markdown(
            f'<div class="panel"><div class="eyebrow">ANALYTICS</div>'
            f'<div class="panel-title">{t["distribution"]}</div>',
            unsafe_allow_html=True,
        )
        if total:
            for label, count, color in [
                (t["low"], low, "#35d6a0"),
                (t["medium"], medium, "#f5bd58"),
                (t["high"], high, "#ff697b"),
                (t["inconclusive"], inconclusive, "#91a5ba"),
            ]:
                pct = round(count / total * 100)
                st.markdown(
                    f'<div class="risk-row"><div class="risk-row-top"><span>{label}</span>'
                    f'<strong style="color:white">{count} ({pct}%)</strong></div>'
                    f'<div class="progress"><div class="progress-fill" style="width:{pct}%;background:{color}"></div></div></div>',
                    unsafe_allow_html=True,
                )
        else:
            st.markdown(f'<div class="empty-state">{t["dashboard_empty"]}</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with right:
        counts = {}
        for item in history:
            counts[item["qrType"]] = counts.get(item["qrType"], 0) + 1
        st.markdown(
            f'<div class="panel"><div class="eyebrow">CONTENT</div>'
            f'<div class="panel-title">{t["qr_types"]}</div>',
            unsafe_allow_html=True,
        )
        if counts:
            for name, count in sorted(counts.items(), key=lambda pair: pair[1], reverse=True)[:6]:
                st.markdown(
                    f'<div class="type-row"><span>{esc(format_label(name))}</span>'
                    f'<strong style="color:white">{count}</strong></div>',
                    unsafe_allow_html=True,
                )
        else:
            st.markdown(f'<div class="empty-state">{t["dashboard_empty"]}</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown(
        f'<div class="panel"><div class="eyebrow">ACTIVITY</div>'
        f'<div class="panel-title">{t["recent"]}</div>',
        unsafe_allow_html=True,
    )
    if history:
        for item in history[:10]:
            risk = str(item["risk"]).lower()
            try:
                date_label = datetime.fromisoformat(item["scannedAt"]).strftime("%d %b %Y, %I:%M %p")
            except Exception:
                date_label = item["scannedAt"]
            st.markdown(
                f'<div class="history-row"><div><strong>{esc(format_label(item["qrType"]))}</strong>'
                f'<div style="font-size:11px;margin-top:5px">{t["scan_date"]}: {esc(date_label)}</div></div>'
                f'<span class="risk-badge risk-{risk}">{esc(risk_label(item["risk"], t))}</span></div>',
                unsafe_allow_html=True,
            )
    else:
        st.markdown(f'<div class="empty-state">{t["no_history"]}</div>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# SCANNER
# ============================================================

def render_scanner():
    st.markdown(
        f'<div class="eyebrow">{t["platform"]}</div>'
        f'<div class="page-title">{t["scanner_title"]}</div>'
        f'<div class="page-subtitle">{t["scanner_sub"]}</div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div class="upload-panel">', unsafe_allow_html=True)
    st.markdown(
        f'<div style="display:flex;gap:13px;align-items:center">'
        f'<div style="font-size:28px;color:#54dce9">⌗</div><div>'
        f'<div style="font-weight:800;color:#edf4fc">{t["scanner_title"]}</div>'
        f'<div style="font-size:12px;color:#91a5ba">{t["scanner_sub"]}</div></div></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        f'<div class="upload-zone"><div class="upload-icon">⇧</div>'
        f'<h3>{t["upload_title"]}</h3><p>{t["upload_sub"]}</p>'
        f'<small>{t["formats"]}</small></div>',
        unsafe_allow_html=True,
    )

    uploaded = st.file_uploader(
        t["file"], type=["png", "jpg", "jpeg", "webp"],
        accept_multiple_files=False, key="qr_uploader",
    )
    file_bytes = None
    if uploaded is not None:
        file_bytes = uploaded.getvalue()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        if file_hash != st.session_state.uploaded_file_hash:
            st.session_state.uploaded_file_hash = file_hash
            st.session_state.scan_data = None
            st.session_state.error = ""

        if len(file_bytes) > 5 * 1024 * 1024:
            st.error(t["error_size"])
            file_bytes = None
        else:
            image_col, detail_col = st.columns([1, 2])
            with image_col:
                st.image(file_bytes, caption=uploaded.name, use_container_width=True)
            with detail_col:
                st.markdown(f"**{t['file']}**")
                st.write(uploaded.name)
                st.caption(f"{len(file_bytes) / 1024:.1f} KB")

    if st.session_state.error:
        st.error(st.session_state.error)

    scan_clicked = st.button(
        f"⌗  {t['analyze']}", disabled=file_bytes is None,
        use_container_width=True, key="analyze_button",
    )

    if scan_clicked and file_bytes:
        st.session_state.error = ""
        st.session_state.scan_data = None
        with st.spinner(t["loading"]):
            try:
                decoded = decode_qr_image(file_bytes)
                if not isinstance(decoded, dict) or not decoded.get("success"):
                    st.session_state.error = (
                        decoded.get("message", t["no_qr"])
                        if isinstance(decoded, dict) else t["no_qr"]
                    )
                else:
                    decoded_items = decoded.get("results", [])
                    if not isinstance(decoded_items, list):
                        raise ValueError(t["error_analysis"])
                    analyses = []
                    for decoded_item in decoded_items:
                        payload = get_decoded_content(decoded_item)
                        if not payload:
                            continue
                        result = analyze_qr_content(
                            payload,
                            external_check=None,
                            language=st.session_state.language,
                        )
                        if isinstance(result, dict):
                            analyses.append(result)
                    if not analyses:
                        st.session_state.error = t["no_qr"]
                    else:
                        st.session_state.scan_data = {
                            "success": True,
                            "total_qr_codes": len(analyses),
                            "results": analyses,
                        }
                        save_history(analyses)
            except Exception as exc:
                st.session_state.error = f'{t["error_analysis"]} ({exc})'

    st.markdown("</div>", unsafe_allow_html=True)

    data = st.session_state.scan_data
    if data:
        st.markdown("---")
        heading_col, button_col = st.columns([3, 1])
        with heading_col:
            st.markdown(
                f'<div class="eyebrow">{t["completed"]}</div>'
                f'<div class="page-title">{t["report"]}</div>'
                f'<div class="page-subtitle">{data["total_qr_codes"]} {t["qr"]}</div>',
                unsafe_allow_html=True,
            )
        with button_col:
            if st.button(f"↻  {t['new_scan']}", use_container_width=True):
                st.session_state.scan_data = None
                st.session_state.uploaded_file_hash = None
                st.session_state.error = ""
                st.rerun()
        for index, item in enumerate(data["results"]):
            render_report(item, index)


# ============================================================
# PAGE ROUTING + FOOTER
# ============================================================

if st.session_state.page == "dashboard":
    render_dashboard()
else:
    render_scanner()

st.markdown(
    f'<div class="footer"><strong>🛡 {t["footer"]}</strong>'
    f'<p>{t["disclaimer"]}</p></div>',
    unsafe_allow_html=True,
)
