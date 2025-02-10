import re
import email
from email import policy
from email.parser import BytesParser

# Common phishing indicators
PHISHING_INDICATORS = [
    r'\burgent\b',
    r'\bverify\b',
    r'\baccount\b',
    r'\bupdate\b',
    r'\bclick here\b',
    r'\bconfirm\b',
    r'\bpassword\b',
    r'\blogin\b',
]

# Function to check for suspicious links
def has_suspicious_links(content):
    # Regex to find URLs
    urls = re.findall(r'(https?://[^\s]+)', content)
    for url in urls:
        # Check for common phishing patterns (e.g., misspelled domains)
        if 'login' in url or 'update' in url:
            return True
    return False

# Function to check for urgent language
def has_urgent_language(content):
    for indicator in PHISHING_INDICATORS:
        if re.search(indicator, content, re.IGNORECASE):
            return True
    return False

# Function to analyze email content
def analyze_email(email_content):
    # Parse the email content
    msg = BytesParser(policy=policy.default).parsebytes(email_content)
    
    # Get the email body
    if msg.is_multipart():
        body = ''.join(part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore') for part in msg.iter_parts())
    else:
        body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')

    # Check for phishing indicators
    if has_suspicious_links(body) or has_urgent_language(body):
        return True  # Potential phishing email
    return False  # Not a phishing email

# Example usage
if __name__ == "__main__":
    # Sample email content (in bytes)
    real_email = b"""From: akbarhussainasadi@gmail.com
To: user@domain.com
Subject: Urgent: Please verify your account

Dear User,

We noticed some suspicious activity on your account. Please click here to verify your account immediately.

Thank you,
Support Team
"""

    if analyze_email(real_email):
        print("This email is potentially a phishing attempt.")
    else:
        print("This email seems safe.")