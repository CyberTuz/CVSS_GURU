"""
Build the AI Scorer benchmark dataset from NVD.

Picks CVEs published in 2024 whose CVSS v3.1 vector was assigned by NVD itself
(source nvd@nist.gov, type Primary), stratified by vulnerability class so that
hard cases (Adjacent/Physical vectors, Scope Changed, High complexity, ...) are
represented. The NVD vector is used as the reference answer.

Usage:
    python scripts/ai_benchmark/build_dataset.py
"""

import json
import os
import random
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv()

OUT = Path(__file__).parent / "dataset.json"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WINDOW = ("2024-02-01T00:00:00.000", "2024-05-29T23:59:59.999")  # NVD allows max 120 days

# (keyword, how many to take)
STRATA = [
    ("cross-site scripting", 4), ("SQL injection", 3), ("path traversal", 2),
    ("server-side request forgery", 2), ("deserialization", 2), ("command injection", 3),
    ("buffer overflow", 3), ("use-after-free", 2), ("privilege escalation", 3),
    ("denial of service", 3), ("Bluetooth", 2), ("physical access", 2),
    ("race condition", 2), ("man-in-the-middle", 2), ("cross-site request forgery", 2),
    ("authentication bypass", 3), ("information disclosure", 2), ("sandbox escape", 1),
    ("hard-coded credentials", 2),
]


def fetch(keyword: str) -> list[dict]:
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.getenv("NVD_API_KEY") else {}
    r = httpx.get(NVD, params={
        "keywordSearch": keyword, "pubStartDate": WINDOW[0], "pubEndDate": WINDOW[1],
        "resultsPerPage": 300,
    }, headers=headers, timeout=60)
    r.raise_for_status()
    return r.json().get("vulnerabilities", [])


def nvd_primary_v31(cve: dict) -> str | None:
    for m in cve.get("metrics", {}).get("cvssMetricV31", []):
        if m.get("source") == "nvd@nist.gov" and m.get("type") == "Primary":
            return m["cvssData"]["vectorString"]
    return None


def main() -> None:
    random.seed(42)
    picked, seen = [], set()
    for keyword, n in STRATA:
        items = fetch(keyword)
        cands = []
        for v in items:
            cve = v["cve"]
            if cve["id"] in seen or cve.get("vulnStatus") == "Rejected":
                continue
            vec = nvd_primary_v31(cve)
            desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
            if vec and 120 <= len(desc) <= 1200:
                cands.append({"id": cve["id"], "category": keyword, "description": desc.strip(), "vector": vec})
        random.shuffle(cands)
        # prefer distinct vectors within a stratum
        taken, vecs = [], set()
        for c in cands:
            if c["vector"] not in vecs:
                taken.append(c); vecs.add(c["vector"])
            if len(taken) == n:
                break
        for c in taken:
            seen.add(c["id"])
        picked += taken
        print(f"{keyword:30s} candidates={len(cands):3d} taken={len(taken)}")
        time.sleep(1.5)

    random.shuffle(picked)
    # First 15 = dev (prompt iteration), rest = test (final comparison only)
    for i, c in enumerate(picked):
        c["split"] = "dev" if i < 15 else "test"
    OUT.write_text(json.dumps(picked, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\n{len(picked)} cases -> {OUT}")


if __name__ == "__main__":
    main()
