# PhishGuard AI - Flask Phishing Email Detector

A complete local Flask website/API for the Kaggle phishing detector saved as:

- `model/phishing_detector.pkl`
- `model/preprocessor.pkl`

## 1. Put your PKL files here

Copy your two files into:

```text
model/
├── phishing_detector.pkl
└── preprocessor.pkl
```

The detector pickle was created from a custom `PhishingEmailDetector` class, so `app.py` intentionally contains the same `TextPreprocessor` class before `joblib.load()`.

## 2. Create a virtual environment (recommended)

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### macOS/Linux

```bash
python3 -m venv venv
source venv/bin/activate
```

## 3. Install packages

```bash
pip install -r requirements.txt
```

If your saved pickle was created with a different scikit-learn version and loading gives a compatibility warning/error, install the same scikit-learn version used in Kaggle when the model was trained.

## 4. Run

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## 5. API

### Health

`GET /api/health`

### Predict

`POST /api/predict`

JSON body:

```json
{
  "email": "Dear customer, your account has been suspended..."
}
```

Example response:

```json
{
  "success": true,
  "prediction": "PHISHING",
  "is_phishing": true,
  "confidence": 87.3,
  "safe_probability": 12.7,
  "phishing_probability": 87.3,
  "threshold": 44.0,
  "features": {
    "urls_detected": 1,
    "emails_detected": 0,
    "matched_keywords": ["account", "click", "verify"],
    "suspicious_patterns": ["High number of phishing-related keywords", "1 link(s) detected"]
  }
}
```

## Important

Do not upload the `.pkl` files to the public frontend or expose them through `/static`. They belong only in the server-side `model/` directory.
"# phishing_email" 
