# TrustCheck QR Detection Module

Beginner-friendly starter scaffold for the TrustCheck QR feature.

## Included now
- FastAPI backend
- QR image decoding using OpenCV
- Single/multiple QR detection attempt
- Upload size and MIME-type checks
- Placeholder modules for classification, parsing, risk analysis and Google Web Risk

## Important
The classifier, parser, risk engine and Google Web Risk integration are placeholders.
Do not present their output as a completed security assessment yet.
A result of `INCONCLUSIVE` is intentional until the analysis pipeline is implemented.

## Install
From the TrustCheck project root, open a VS Code terminal and run:

```powershell
python -m pip install -r requirements.txt
```

## Run
From the TrustCheck project root:

```powershell
python -m uvicorn backend.main:app --reload
```

Open:
- http://127.0.0.1:8000
- http://127.0.0.1:8000/docs

## Google Web Risk setup later
1. Copy `backend/.env.example` to `backend/.env`.
2. Add your Google Web Risk API key to `backend/.env`.
3. Keep `.env` out of GitHub. It is ignored by `.gitignore`.

## Next development stages
1. Complete QR classifier.
2. Implement parsers for each QR format.
3. Implement safe URL reputation checks with Google Web Risk.
4. Implement evidence-based risk assessment.
5. Connect uploaded images and live camera scans to the same analyzer.
6. Build the React + Vite user interface.
