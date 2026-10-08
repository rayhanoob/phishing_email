from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
import numpy as np
import re
import os
from sklearn.base import BaseEstimator, TransformerMixin

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "model")
DETECTOR_PATH = os.path.join(MODEL_DIR, "phishing_detector.pkl")
PREPROCESSOR_PATH = os.path.join(MODEL_DIR, "preprocessor.pkl")


# IMPORTANT:
# This class must exist before joblib loads phishing_detector.pkl because
# the saved detector contains an instance of this custom class.
class TextPreprocessor(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.phishing_keywords = [
            'urgent', 'verify', 'account', 'password', 'login', 'security',
            'update', 'suspended', 'limited', 'confirm', 'click', 'link',
            'winner', 'prize', 'free', 'offer', 'congratulations', 'dear',
            'immediately', 'action required', 'verify your account', 'bank',
            'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook'
        ]

    def fit(self, X, y=None):
        return self

    def transform(self, X, y=None):
        X_processed = X.copy()
        if isinstance(X, pd.Series):
            X_processed = X_processed.apply(self._clean_text)
        return X_processed

    def _clean_text(self, text):
        if pd.isna(text):
            return ""

        text = str(text).lower()
        text = re.sub(r'https?://\S+|www\.\S+', ' [URL] ', text)
        text = re.sub(r'\S+@\S+', ' [EMAIL] ', text)
        text = re.sub(r'[\+\d\-\s\(\)]{10,}', ' [PHONE] ', text)
        text = re.sub(r'[^\w\s\.\,\!\?\:\;\$\%]', ' ', text)
        text = re.sub(r'\d+', ' [NUMBER] ', text)
        text = ' '.join(text.split())
        return text

    def extract_features(self, text):
        features = {}
        text_lower = text.lower()
        features['keyword_count'] = sum(
            1 for keyword in self.phishing_keywords if keyword in text_lower
        )
        features['text_length'] = len(text)
        features['word_count'] = len(text.split())
        features['avg_word_length'] = (
            np.mean([len(w) for w in text.split()]) if text.split() else 0
        )
        features['url_count'] = len(re.findall(r'\[URL\]', text))
        features['email_count'] = len(re.findall(r'\[EMAIL\]', text))
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        features['dollar_count'] = text.count('$') + text.count('£') + text.count('€')
        return features



class PhishingEmailDetector:
    def __init__(self, model, preprocessor, threshold=0.5):
        self.model = model
        self.preprocessor = preprocessor
        self.threshold = threshold
        self.text_preprocessor = TextPreprocessor()

    def predict(self, email_text, return_confidence=False):
        # Clean email text
        processed_text = self.text_preprocessor._clean_text(email_text)

        # Extract features
        features = self.text_preprocessor.extract_features(processed_text)

        # Create input DataFrame
        input_data = pd.DataFrame([{
            'processed_text': processed_text,
            **features
        }])

        # Transform using trained preprocessor
        transformed_input = self.preprocessor.transform(input_data)

        # Get probabilities
        probabilities = self.model.predict_proba(transformed_input)[0]

        # Phishing probability
        confidence = probabilities[1]

        # Apply trained threshold
        prediction = 1 if confidence >= self.threshold else 0

        if return_confidence:
            return prediction, confidence, probabilities

        return prediction

    def predict_batch(self, email_texts, return_confidence=False):
        predictions = []
        confidences = []

        for text in email_texts:

            if return_confidence:
                pred, conf, _ = self.predict(
                    text,
                    return_confidence=True
                )

                predictions.append(pred)
                confidences.append(conf)

            else:
                predictions.append(self.predict(text))

        if return_confidence:
            return np.array(predictions), np.array(confidences)

        return np.array(predictions)

    def set_threshold(self, new_threshold):
        self.threshold = new_threshold

    def explain_prediction(self, email_text):

        prediction, confidence, probabilities = self.predict(
            email_text,
            return_confidence=True
        )

        explanation = {
            'prediction': 'PHISHING' if prediction == 1 else 'SAFE',
            'confidence': confidence,
            'safe_probability': probabilities[0],
            'phishing_probability': probabilities[1],
            'threshold_used': self.threshold
        }

        processed_text = self.text_preprocessor._clean_text(
            email_text
        )

        features = self.text_preprocessor.extract_features(
            processed_text
        )

        explanation['features'] = {
            'keyword_count': features['keyword_count'],
            'text_length': features['text_length'],
            'url_count': features['url_count'],
            'suspicious_patterns': []
        }

        if features['keyword_count'] > 3:
            explanation['features']['suspicious_patterns'].append(
                'High keyword count'
            )

        if features['url_count'] > 1:
            explanation['features']['suspicious_patterns'].append(
                'Multiple URLs'
            )

        if features['dollar_count'] > 0:
            explanation['features']['suspicious_patterns'].append(
                'Financial references'
            )

        return explanation
# Load the saved detector.
# The class above MUST be defined before this line.
try:

    print("Loading phishing detector...")
    detector = joblib.load(DETECTOR_PATH)

    print("Loading preprocessor...")
    saved_preprocessor = joblib.load(PREPROCESSOR_PATH)

    MODEL_ERROR = None

    print("=================================")
    print("MODEL LOADED SUCCESSFULLY")
    print("=================================")

except Exception as exc:

    detector = None
    saved_preprocessor = None

    MODEL_ERROR = repr(exc)

    print("=================================")
    print("MODEL LOADING FAILED")
    print("=================================")
    print(MODEL_ERROR)
    print("=================================")


def analyze_extra_signals(email_text):
    """Extra human-readable signals for the website UI.
    These do not change the ML prediction.
    """
    text = email_text or ""
    lower = text.lower()

    urls = re.findall(r'https?://\S+|www\.\S+', text, flags=re.I)
    emails = re.findall(r'\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b', text)

    keywords = getattr(detector.text_preprocessor, 'phishing_keywords', []) if detector else []
    matched_keywords = sorted({k for k in keywords if k in lower})

    patterns = []
    if len(matched_keywords) > 3:
        patterns.append('High number of phishing-related keywords')
    if len(urls) > 0:
        patterns.append(f'{len(urls)} link(s) detected')
    if len(urls) > 1:
        patterns.append('Multiple URLs')
    if re.search(r'\b(password|login|verify|account|security)\b', lower):
        patterns.append('Account/security language')
    if re.search(r'\b(urgent|immediately|action required|suspended|limited time)\b', lower):
        patterns.append('Urgency or pressure language')
    if re.search(r'\b(win|winner|prize|gift card|free money|congratulations)\b', lower):
        patterns.append('Prize/reward language')
    if re.search(r'[$£€]\s?\d+', text):
        patterns.append('Financial amount detected')

    return {
        'urls_detected': len(urls),
        'emails_detected': len(emails),
        'matched_keywords': matched_keywords,
        'suspicious_patterns': patterns
    }


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok' if detector is not None else 'error',
        'model_loaded': detector is not None,
        'preprocessor_loaded': saved_preprocessor is not None,
        'model_error': MODEL_ERROR
    })


@app.route('/api/predict', methods=['POST'])
def predict():
    if detector is None:
        return jsonify({
            'success': False,
            'error': 'Model could not be loaded.',
            'details': MODEL_ERROR
        }), 500

    try:
        data = request.get_json(silent=True) or {}
        email_text = str(data.get('email', '')).strip()

        if not email_text:
            return jsonify({
                'success': False,
                'error': 'Please enter an email message.'
            }), 400

        if len(email_text) > 100000:
            return jsonify({
                'success': False,
                'error': 'Email is too long. Maximum length is 100,000 characters.'
            }), 400

        prediction, confidence, probabilities = detector.predict(
            email_text, return_confidence=True
        )

        confidence = float(confidence)
        safe_probability = float(probabilities[0])
        phishing_probability = float(probabilities[1])

        extra = analyze_extra_signals(email_text)

        result = 'PHISHING' if int(prediction) == 1 else 'SAFE'
        threshold = float(getattr(detector, 'threshold', 0.5))

        return jsonify({
            'success': True,
            'prediction': result,
            'is_phishing': bool(int(prediction) == 1),
            'confidence': round(confidence * 100, 2),
            'safe_probability': round(safe_probability * 100, 2),
            'phishing_probability': round(phishing_probability * 100, 2),
            'threshold': round(threshold * 100, 2),
            'text_length': len(email_text),
            'features': extra
        })

    except Exception as exc:
        return jsonify({
            'success': False,
            'error': 'Prediction failed.',
            'details': str(exc)
        }), 500


@app.errorhandler(404)
def not_found(_error):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'API endpoint not found.'}), 404
    return render_template('index.html'), 404


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
