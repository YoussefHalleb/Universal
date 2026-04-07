import json
import os
import subprocess
import re
import requests
import sys


def load_trivy(path="trivy.json"):
    if not os.path.exists(path):
        print(f"Trivy file not found: {path}")
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def detect_package_manager(target: str, result_type: str) -> str:
    t = (target or "").lower()
    rt = (result_type or "").lower()

    if "node_modules" in t or t.endswith(".json") or rt in ("node-pkg", "npm"):
        return "npm"
    if "requirements" in t or t.endswith(".txt") or "pip" in rt:
        return "pip"
    if "alpine" in t or "apk" in t:
        return "apk"
    return "apt"


def extract_critical_vulns(data, max_vulns=10):
    vulns = []

    for result in data.get("Results", []):
        result_type = result.get("Type", "")
        target = result.get("Target", "")

        print(f"Type={result_type} Target={target}")

        if result_type not in ("node-pkg", "npm", "os-pkgs"):
            print(f"  ⏭ Skipping unsupported type: {result_type} — {target}")
            continue

        pkg_manager = detect_package_manager(target, result_type)

        for v in result.get("Vulnerabilities", []) or []:
            if v.get("Severity") in ("CRITICAL", "HIGH") and v.get("FixedVersion"):
                vulns.append({
                    "pkg": v.get("PkgName"),
                    "installed": v.get("InstalledVersion"),
                    "fixed": v.get("FixedVersion"),
                    "cve": v.get("VulnerabilityID"),
                    "title": v.get("Title", ""),
                    "target": target,
                    "type": result_type,
                    "package_manager": pkg_manager,
                })

    return vulns[:max_vulns]


def ask_groq_for_fix(vulns):
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY is missing")

    resp = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": "llama-3.1-8b-instant",
            "temperature": 0.1,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a senior security engineer. "
                        "Return only valid JSON, no markdown, no explanation."
                    ),
                },
                {
                    "role": "user",
                    "content": f"""
Given these Trivy vulnerabilities, return ONLY a JSON array of fixes.

Command rules by package manager:
- alpine packages -> "apk upgrade PACKAGE"
- apt packages    -> "apt-get install -y --only-upgrade PACKAGE=VERSION"
- npm packages    -> "npm install PACKAGE@VERSION --save"
- pip packages    -> "pip install PACKAGE==VERSION"

Use the provided "package_manager" field directly if present.

Return format:
[{{"pkg": "package-name", "cmd": "the exact command", "cve": "CVE-XXXX-XXXX"}}]

Rules:
- Only include packages that have a non-empty FixedVersion.
- No markdown.
- No explanation.
- JSON array only.

Vulnerabilities:
{json.dumps(vulns, indent=2)}
""",
                },
            ],
        },
        timeout=30,
    )
    resp.raise_for_status()

    raw = resp.json()["choices"][0]["message"]["content"].strip()
    raw = re.sub(r"```json|```", "", raw).strip()

    try:
        data = json.loads(raw)
        if not isinstance(data, list):
            print("Groq response is not a list, returning empty fixes.")
            return []
        return data
    except json.JSONDecodeError:
        print("Failed to parse Groq JSON response.")
        print("Raw response:")
        print(raw)
        return []


def normalize_command(cmd: str) -> str:
    cmd = (cmd or "").strip()

    if not cmd:
        return ""

    if cmd.startswith("apt-get") and not cmd.startswith("sudo "):
        return "sudo " + cmd

    if cmd.startswith("apk") and not cmd.startswith("sudo "):
        return "sudo " + cmd

    return cmd


def apply_fixes(fixes):
    applied = []
    app_dir = "target-app" if os.path.exists("target-app") else "."
    print(f"Applying fixes in: {app_dir}")

    for fix in fixes:
        cmd = normalize_command(fix.get("cmd", ""))
        if not cmd:
            print(f"  ⏭ Skipping empty command for {fix.get('pkg')} ({fix.get('cve')})")
            continue

        print(f"Applying: {cmd}")
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            cwd=app_dir,
        )

        if result.returncode == 0:
            applied.append(fix)
            print(f"  ✓ Fixed {fix.get('pkg')} ({fix.get('cve')})")
        else:
            print(f"  ✗ Failed: {result.stderr.strip()}")

    return applied


if __name__ == "__main__":
    data = load_trivy()
    vulns = extract_critical_vulns(data)

    if not vulns:
        print("No critical/high vulns with fixes found.")
        with open("fix_summary.json", "w", encoding="utf-8") as f:
            json.dump({"applied": [], "vulns": []}, f, indent=2)
        sys.exit(0)

    print(f"Found {len(vulns)} critical/high vulnerabilities")

    try:
        fixes = ask_groq_for_fix(vulns)
    except Exception as e:
        print(f"Failed to get fixes from Groq: {e}")
        fixes = []

    applied = apply_fixes(fixes)

    with open("fix_summary.json", "w", encoding="utf-8") as f:
        json.dump({"applied": applied, "vulns": vulns}, f, indent=2)

    print(f"Applied {len(applied)} fixes.")
