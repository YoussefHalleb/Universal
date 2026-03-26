import json, os, subprocess, re
import requests

def load_trivy(path="trivy.json"):
    with open(path) as f:
        return json.load(f)

def extract_critical_vulns(data, max_vulns=5):
    vulns = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities", []) or []:
            if v.get("Severity") in ("CRITICAL", "HIGH"):
                vulns.append({
                    "pkg": v.get("PkgName"),
                    "installed": v.get("InstalledVersion"),
                    "fixed": v.get("FixedVersion"),
                    "cve": v.get("VulnerabilityID"),
                    "title": v.get("Title", ""),
                    "target": result.get("Target", ""),
                })
    return vulns[:max_vulns]

def ask_groq_for_fix(vulns):
    resp = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {os.environ['GROQ_API_KEY']}",
            "Content-Type": "application/json"
        },
        json={
            "model": "llama-3.1-8b-instant",
            "temperature": 0.1,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a senior security engineer. Return only valid JSON, no markdown, no explanation."
                },
                {
                    "role": "user",
                    "content": f"""
Given these Trivy vulnerabilities, return ONLY a JSON array of fixes:
[{{"pkg": "package-name", "cmd": "npm install pkg@fixed_version --save", "cve": "CVE-XXXX-XXXX"}}]

Rules:
- Use npm/pip/apt depending on the target file
- Only include packages that have a FixedVersion
- No markdown, no explanation, just the JSON array

Vulnerabilities:
{json.dumps(vulns, indent=2)}
"""
                }
            ]
        },
        timeout=30
    )
    resp.raise_for_status()
    raw = resp.json()["choices"][0]["message"]["content"].strip()
    raw = re.sub(r"```json|```", "", raw).strip()
    return json.loads(raw)

def apply_fixes(fixes):
    applied = []
    for fix in fixes:
        print(f"Applying: {fix['cmd']}")
        result = subprocess.run(fix["cmd"], shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            applied.append(fix)
            print(f"  ✓ Fixed {fix['pkg']} ({fix['cve']})")
        else:
            print(f"  ✗ Failed: {result.stderr}")
    return applied

if __name__ == "__main__":
    data = load_trivy()
    vulns = extract_critical_vulns(data)

    if not vulns:
        print("No critical/high vulns with fixes found.")
        exit(0)

    print(f"Found {len(vulns)} critical/high vulnerabilities")
    fixes = ask_groq_for_fix(vulns)
    applied = apply_fixes(fixes)

    with open("fix_summary.json", "w") as f:
        json.dump({"applied": applied, "vulns": vulns}, f)

    print(f"Applied {len(applied)} fixes.")
