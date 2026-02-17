import requests, os, sys
from datetime import date

DD_URL = os.getenv("DEFECTDOJO_URL")
DD_TOKEN = os.getenv("DEFECTDOJO_API_KEY")
REPO = os.getenv("GITHUB_REPOSITORY")
BUILD = os.getenv("GITHUB_RUN_NUMBER")

if not DD_URL or not DD_TOKEN:
    print("Missing DefectDojo configuration")
    sys.exit(1)

headers = {"Authorization": f"Token {DD_TOKEN}"}

# Get or create Product
product_name = REPO.replace("/", "_")
r = requests.get(f"{DD_URL}/api/v2/products/?name={product_name}", headers=headers)
if r.json()["count"] > 0:
    product_id = r.json()["results"][0]["id"]
else:
    r = requests.post(
        f"{DD_URL}/api/v2/products/",
        headers=headers,
        json={
            "name": product_name,
            "description": f"Auto-created for {REPO}",
            "prod_type": 1
        }
    )
    product_id = r.json()["id"]

# Create Engagement
r = requests.post(
    f"{DD_URL}/api/v2/engagements/",
    headers=headers,
    json={
        "name": f"CI Build {BUILD}",
        "product": product_id,
        "target_start": str(date.today()),
        "target_end": str(date.today()),
        "status": "In Progress",
        "engagement_type": "CI/CD"
    }
)
engagement_id = r.json()["id"]

# Import Trivy
if os.path.exists("trivy.json"):
    requests.post(
        f"{DD_URL}/api/v2/import-scan/",
        headers=headers,
        files={"file": open("trivy.json", "rb")},
        data={
            "engagement": engagement_id,
            "scan_type": "Trivy Scan",
            "minimum_severity": "Low",
            "active": True,
            "verified": True
        }
    )

# Import ZAP
if os.path.exists("zap.xml"):
    requests.post(
        f"{DD_URL}/api/v2/import-scan/",
        headers=headers,
        files={"file": open("zap.xml", "rb")},
        data={
            "engagement": engagement_id,
            "scan_type": "ZAP Scan",
            "minimum_severity": "Low",
            "active": True,
            "verified": True
        }
    )

print("DefectDojo upload completed.")
