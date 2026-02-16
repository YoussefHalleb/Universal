import json
import os
import requests
import xml.etree.ElementTree as ET

# =====================
# CONFIG
# =====================
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
API_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL = "llama-3.1-8b-instant"
MAX_ITEMS = 6
TIMEOUT = 60

if not GROQ_API_KEY:
    print("❌ GROQ_API_KEY not set")
    exit(1)

headers = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
}

summary = ""
count = 0

# =====================
# TRIVY (SCA / IMAGE)
# =====================
if os.path.exists("trivy.json"):
    try:
        with open("trivy.json") as f:
            data = json.load(f)

        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                if count >= MAX_ITEMS:
                    break

                summary += f"""
### [SCA - Trivy]
- **ID**: {vuln.get('VulnerabilityID')}
- **Severity**: {vuln.get('Severity')}
- **Package**: {vuln.get('PkgName')}
- **Description**: {vuln.get('Description')}
"""
                count += 1
    except Exception as e:
        summary += f"\n⚠️ Error parsing trivy.json: {e}\n"

# =====================
# ZAP (DAST)
# =====================
if os.path.exists("zap.xml"):
    try:
        tree = ET.parse("zap.xml")
        root = tree.getroot()

        for alert in root.findall(".//alertitem"):
            if count >= MAX_ITEMS * 2:
                break

            summary += f"""
### [DAST - OWASP ZAP]
- **Vulnerability**: {alert.findtext('alert')}
- **Risk**: {alert.findtext('riskdesc')}
- **URL**: {alert.findtext('uri')}
- **Description**: {alert.findtext('desc')}
"""
            count += 1
    except Exception as e:
        summary += f"\n⚠️ Error parsing zap.xml: {e}\n"

if not summary.strip():
    summary = "No vulnerabilities detected by Trivy or OWASP ZAP."

# =====================
# AI PROMPT
# =====================
prompt = f"""
You are a senior DevSecOps and Application Security expert.

Analyze the following SCA (Trivy) and DAST (OWASP ZAP) findings.

For EACH vulnerability:
1. Explain how it can be exploited
2. Describe the technical and business impact
3. Provide concrete remediation steps
4. Reference OWASP Top 10 or security best practices

Findings:
{summary}
"""

payload = {
    "model": MODEL,
    "messages": [
        {"role": "system", "content": "You are a senior application security engineer."},
        {"role": "user", "content": prompt}
    ],
    "temperature": 0.2
}

# =====================
# GROQ API CALL
# =====================
response = requests.post(
    API_URL,
    headers=headers,
    json=payload,
    timeout=TIMEOUT
)

if response.status_code != 200:
    print("❌ Groq API error:", response.text)
    exit(1)

result = response.json()
analysis = result["choices"][0]["message"]["content"]

# =====================
# OUTPUT
# =====================
with open("ai_security_recommendations.md", "w") as f:
    f.write("# 🛡️ AI Security Recommendations\n\n")
    f.write(analysis)

print("✅ AI security recommendations generated successfully.")
