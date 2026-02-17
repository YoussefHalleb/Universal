import requests
import os
import sys
from datetime import date

DD_URL = os.getenv("DEFECTDOJO_URL")
DD_TOKEN = os.getenv("DEFECTDOJO_API_KEY")
REPO = os.getenv("GITHUB_REPOSITORY")
BUILD = os.getenv("GITHUB_RUN_NUMBER")
COMMIT = os.getenv("GITHUB_SHA")

if not DD_URL or not DD_TOKEN:
    print("❌ Missing DefectDojo configuration")
    sys.exit(1)

# Remove trailing slash if exists
DD_URL = DD_URL.rstrip("/")

headers = {
    "Authorization": f"Token {DD_TOKEN}",
    "Content-Type": "application/json"
}

def safe_json(response):
    try:
        return response.json()
    except Exception:
        print("❌ Response is not valid JSON")
        print("Status Code:", response.status_code)
        print("Response Text:", response.text)
        sys.exit(1)

# ================================
# Create or Get Product
# ================================
product_name = REPO.replace("/", "_")
print(f"📦 Using product name: {product_name}")

r = requests.get(
    f"{DD_URL}/api/v2/products/?name={product_name}",
    headers=headers
)

if r.status_code != 200:
    print("❌ Failed to connect to DefectDojo API (Products)")
    print("Status:", r.status_code)
    print(r.text)
    sys.exit(1)

data = safe_json(r)

if data.get("count", 0) > 0:
    product_id = data["results"][0]["id"]
    print("✔ Product exists.")
else:
    print("🆕 Creating new product...")
    r = requests.post(
        f"{DD_URL}/api/v2/products/",
        headers=headers,
        json={
            "name": product_name,
            "description": f"Auto-created for {REPO}",
            "prod_type": 1
        }
    )

    if r.status_code not in [200, 201]:
        print("❌ Failed to create product")
        print(r.text)
        sys.exit(1)

    product_id = safe_json(r)["id"]

print(f"Using Product ID: {product_id}")

# ================================
# Create Engagement
# ================================
r = requests.post(
    f"{DD_URL}/api/v2/engagements/",
    headers=headers,
    json={
        "name": f"CI Build {BUILD}",
        "product": product_id,
        "target_start": str(date.today()),
        "target_end": str(date.today()),
        "status": "In Progress",
        "engagement_type": "CI/CD",
        "description": f"Commit: {COMMIT}"
    }
)

if r.status_code not in [200, 201]:
    print("❌ Failed to create engagement")
    print(r.text)
    sys.exit(1)

engagement_id = safe_json(r)["id"]
print(f"Using Engagement ID: {engagement_id}")

# ================================
# Import Trivy
# ================================
if os.path.exists("trivy.json"):
    print("🔎 Uploading Trivy results...")
    with open("trivy.json", "rb") as f:
        requests.post(
            f"{DD_URL}/api/v2/import-scan/",
            headers={"Authorization": f"Token {DD_TOKEN}"},
            files={"file": f},
            data={
                "engagement": engagement_id,
                "scan_type": "Trivy Scan",
                "minimum_severity": "Low",
                "active": True,
                "verified": True
            }
        )

# ================================
# Import ZAP
# ================================
if os.path.exists("zap.xml"):
    print("🌐 Uploading ZAP results...")
    with open("zap.xml", "rb") as f:
        requests.post(
            f"{DD_URL}/api/v2/import-scan/",
            headers={"Authorization": f"Token {DD_TOKEN}"},
            files={"file": f},
            data={
                "engagement": engagement_id,
                "scan_type": "ZAP Scan",
                "minimum_severity": "Low",
                "active": True,
                "verified": True
            }
        )

print("✅ DefectDojo upload completed.")

# ================================
# Fail ONLY if this repo has Critical findings
# ================================
r = requests.get(
    f"{DD_URL}/api/v2/findings/?product={product_id}&severity=Critical&active=true",
    headers=headers
)

if r.status_code != 200:
    print("❌ Failed to fetch findings")
    print(r.text)
    sys.exit(1)

critical_count = safe_json(r).get("count", 0)

if critical_count > 0:
    print(f"❌ {critical_count} Critical findings detected in this repository.")
    sys.exit(1)
else:
    print("✅ No Critical findings for this repository.")
