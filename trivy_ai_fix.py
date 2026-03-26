import json, os, subprocess, re
import anthropic

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

def ask_claude_for_fix(vulns):
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    prompt = f"""
You are a senior security engineer. Given these vulnerable packages from a Trivy scan,
generate the exact shell commands needed to update each package to a safe version.

Vulnerabilities:
{json.dumps(vulns, indent=2)}

Rules:
- Return ONLY a JSON array of objects: [{{"pkg": "...", "cmd": "npm install pkg@version --save", "cve": "..."}}]
- Use npm/pip/apt depending on the target file context
- If no fix version is available, skip the package
- No explanations, no markdown, just the JSON array
"""
    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )
    raw = message.content[0].text.strip()
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
    fixes = ask_claude_for_fix(vulns)
    applied = apply_fixes(fixes)
    
    # Save summary for the PR script
    with open("fix_summary.json", "w") as f:
        json.dump({"applied": applied, "vulns": vulns}, f)
    
    print(f"Applied {len(applied)} fixes.")
