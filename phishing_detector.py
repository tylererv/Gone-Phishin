import os
import re
import google.generativeai as genai
from typing import List, Dict
from dataclasses import dataclass
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

# Set up Google Gemini API key
GEMINI_API_KEY ='REPLACE'  # Replace with your actual API key
genai.configure(api_key=GEMINI_API_KEY)

@dataclass
class WarningMessage:
    title: str
    details: str

class PhishingDetector:
    def __init__(self):
        # Rely exclusively on AI.
        pass

    def analyze_email(self, content: str, sender: str = "") -> List[WarningMessage]:
        """
        Analyze email content using Google Gemini AI to determine if it's a phishing attempt.
        """
        ai_warning = self.analyze_with_gemini(content, sender)
        if ai_warning:
            return [ai_warning]
        return []

    def analyze_with_gemini(self, content: str, sender: str) -> WarningMessage:
        """
        Uses the Google Gemini API to analyze the email content and sender.
        The AI is instructed to focus on overall context, linguistic cues, and sender details,
        and return a concise risk summary in about 3 sentences.
        """
        try:
            # Use the gemini-2.0-flash model for the analysis or replace with desired model.
            model = genai.GenerativeModel("gemini-2.0-flash")
            prompt = f"""
            You are a cybersecurity AI expert. Analyze the following email and determine if it is a phishing attempt or if it is safe.
            Consider the overall context, linguistic cues, and sender details, and think logically about the situation.
            Answer in 3 sentences or less.

            Email Sender: {sender}
            Email Content: {content}

            Provide your analysis strictly in the following format:
            Title: (Short title summarizing your analysis)

            Details: (A detailed explanation of your findings)
            """
            response = model.generate_content(prompt)
            ai_result = response.text.strip()  # Full AI response

            # Return the AI summary as a WarningMessage.
            return WarningMessage("AI Risk Summary", ai_result)

        except Exception as e:
            print(f"Error analyzing email with AI: {e}")
            return None

    def get_risk_level(self, warnings: List[WarningMessage]) -> str:
        """
        Determine overall risk level based solely on the AI-generated warning.
        Checks the AI's details for keywords:
          - If it indicates the email is safe, return "none".
          - If it indicates a phishing attempt, return "risky".
          - Otherwise, return "unsure".
        """
        if not warnings:
            return "none"

        warning_text = warnings[0].details.lower()
        if "safe" in warning_text or "not phishing" in warning_text:
            return "none"
        elif "phishing" in warning_text or "scam" in warning_text or "malicious" in warning_text:
            return "risky"
        else:
            return "unsure"

class EmailAnalysis:
    def __init__(self, email_id: str, content: str, sender: str = ""):
        self.email_id = email_id
        self.content = content
        self.sender = sender
        self.timestamp = datetime.now()
        self.detector = PhishingDetector()
        self.warnings = self.detector.analyze_email(content, sender)
        self.risk_level = self.detector.get_risk_level(self.warnings)

    def to_dict(self) -> Dict:
        """
        Convert analysis results to dictionary format.
        """
        return {
            "email_id": self.email_id,
            "timestamp": self.timestamp.isoformat(),
            "sender": self.sender,
            "risk_level": self.risk_level,
            "warnings": [
                {
                    "title": warning.title,
                    "details": warning.details
                }
                for warning in self.warnings
            ]
        }

def analyze_emails(emails: List[Dict[str, str]]) -> List[Dict]:
    """
    Analyze multiple emails using the AI-powered phishing detection.
    Each email dictionary should contain keys: 'id', 'content', and optionally 'sender'.
    """
    results = []
    for email in emails:
        analysis = EmailAnalysis(
            email_id=email['id'],
            content=email['content'],
            sender=email.get('sender', '')
        )
        results.append(analysis.to_dict())
    return results

# Flask App Setup
app = Flask(__name__)
CORS(app)  # Enable CORS so that the Chrome extension can access this API

@app.route('/api/detect-phishing', methods=['POST'])
def detect_phishing():
    """
    API endpoint that analyzes one or more emails for phishing.
    Accepts JSON payload:
      - Either: { "emails": [ { "id": ..., "content": ..., "sender": ... }, ... ] }
      - Or: { "email": { "id": ..., "content": ..., "sender": ... } }
    Returns analysis results in JSON format.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload provided"}), 400

    if "emails" in data:
        results = analyze_emails(data["emails"])
        return jsonify(results)
    elif "email" in data:
        email = data["email"]
        analysis = EmailAnalysis(
            email_id=email['id'],
            content=email['content'],
            sender=email.get('sender', '')
        )
        return jsonify(analysis.to_dict())
    else:
        return jsonify({"error": "Invalid payload structure"}), 400

if __name__ == "__main__":
    print("\nStarting Flask server on port 5002...\n")
    app.run(debug=True, host="0.0.0.0", port=5002)
