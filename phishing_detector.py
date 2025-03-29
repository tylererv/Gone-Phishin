import re
from typing import List, Dict, Tuple
from dataclasses import dataclass
from datetime import datetime

@dataclass
class WarningMessage:
    title: str
    details: str
    severity: str = "medium"

class PhishingPattern:
    def __init__(self, pattern: str, title: str, details: str, severity: str = "medium"):
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.warning = WarningMessage(title, details, severity)

class PhishingDetector:
    def __init__(self):
        self.patterns = [
            PhishingPattern(
                r"(urgent|immediate|action required|account suspended|verify account)",
                "Urgent Action Required",
                "This email contains urgent or threatening language, which is a common phishing tactic.",
                "high"
            ),
            PhishingPattern(
                r"(bit\.ly|goo\.gl|tinyurl\.com|click here)",
                "Suspicious Links Detected",
                "Contains shortened URLs or generic 'click here' links, which may hide malicious destinations.",
                "high"
            ),
            PhishingPattern(
                r"(noreply|support@|account@|security@)",
                "Suspicious Sender Pattern",
                "The sender address matches common phishing patterns (noreply, support, account, security).",
                "medium"
            ),
            PhishingPattern(
                r"(dear valued customer|dear user|dear account holder)",
                "Generic or Suspicious Greeting",
                "Uses generic greetings or poor grammar, which are common in phishing attempts.",
                "low"
            )
        ]

    def analyze_email(self, content: str, sender: str = "") -> List[WarningMessage]:
        """
        Analyze email content for phishing indicators.
        
        Args:
            content: The email content to analyze
            sender: The sender's email address
            
        Returns:
            List of warning messages for detected phishing indicators
        """
        warnings = []
        
        # Analyze content against all patterns
        for pattern in self.patterns:
            if pattern.pattern.search(content):
                warnings.append(pattern.warning)
        
        # Additional sender-specific checks
        if sender:
            self._check_sender(sender, warnings)
        
        return warnings

    def _check_sender(self, sender: str, warnings: List[WarningMessage]) -> None:
        """Perform additional checks on the sender's email address."""
        # Check for domain mismatch
        if "@" in sender:
            domain = sender.split("@")[1]
            if domain.lower() in ["gmail.com", "yahoo.com", "hotmail.com"]:
                warnings.append(WarningMessage(
                    "Personal Email Domain",
                    "Sender is using a personal email domain, which is unusual for official communications.",
                    "medium"
                ))

    def get_risk_level(self, warnings: List[WarningMessage]) -> str:
        """Determine overall risk level based on warnings."""
        if not warnings:
            return "none"
        
        # Count warnings by severity
        severity_counts = {"high": 0, "medium": 0, "low": 0}
        for warning in warnings:
            severity_counts[warning.severity] += 1
        
        # Determine risk level
        if severity_counts["high"] > 0:
            return "high"
        elif severity_counts["medium"] >= 2:
            return "medium"
        elif severity_counts["medium"] == 1 or severity_counts["low"] >= 2:
            return "low"
        return "none"

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
        """Convert analysis results to dictionary format."""
        return {
            "email_id": self.email_id,
            "timestamp": self.timestamp.isoformat(),
            "sender": self.sender,
            "risk_level": self.risk_level,
            "warnings": [
                {
                    "title": warning.title,
                    "details": warning.details,
                    "severity": warning.severity
                }
                for warning in self.warnings
            ]
        }

def analyze_emails(emails: List[Dict[str, str]]) -> List[Dict]:
    """
    Analyze multiple emails for phishing indicators.
    
    Args:
        emails: List of dictionaries containing email data
               Each dict should have 'id', 'content', and optionally 'sender' keys
    
    Returns:
        List of analysis results in dictionary format
    """
    detector = PhishingDetector()
    results = []
    
    for email in emails:
        analysis = EmailAnalysis(
            email_id=email['id'],
            content=email['content'],
            sender=email.get('sender', '')
        )
        results.append(analysis.to_dict())
    
    return results

# Example usage
if __name__ == "__main__":
    # Example email data
    sample_emails = [
        {
            "id": "1",
            "content": "URGENT: Your account has been suspended. Click here to verify your identity.",
            "sender": "noreply@example.com"
        },
        {
            "id": "2",
            "content": "Dear valued customer, please review your recent transaction.",
            "sender": "support@legitimate.com"
        }
    ]
    
    # Analyze emails
    results = analyze_emails(sample_emails)
    
    # Print results
    for result in results:
        print(f"\nEmail ID: {result['email_id']}")
        print(f"Risk Level: {result['risk_level']}")
        print("Warnings:")
        for warning in result['warnings']:
            print(f"- {warning['title']}: {warning['details']}") 