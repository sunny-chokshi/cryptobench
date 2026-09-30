#!/usr/bin/env python3
"""Reproduce the CryptoBench summary tables from results/crypto_results.csv.

Usage:  python3 scripts/analyze.py [results/crypto_results.csv]
Writes results/summary_per_model.csv and results/summary_per_class.csv and
prints both tables. Wilson 95% intervals throughout.
"""
import csv, math, sys, collections, os

SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "results", "crypto_results.csv")
OUT = os.path.dirname(os.path.abspath(SRC))
DISCRIMINATING = {"qwen2.5-coder:7b", "qwen2.5-coder:14b", "deepseek-coder:6.7b"}
CLASS_NAMES = {
    "cert_verify": "Disabled cert verification", "broken_cipher": "Obsolete / broken cipher",
    "ecb_mode": "ECB mode", "weak_hash": "Weak password hash", "static_iv": "Static / reused IV",
    "short_key": "Short asymmetric key", "no_salt": "Unsalted / fast KDF",
    "hardcoded_key": "Hardcoded key / secret", "weak_prng": "Weak PRNG (security value)",
}

def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"),) * 3
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)

rows = list(csv.DictReader(open(SRC)))
models = sorted({r["model"] for r in rows})

per_model = []
for m in models:
    v = [r for r in rows if r["model"] == m and r["label"] == "vuln"]
    s = [r for r in rows if r["model"] == m and r["label"] == "secure"]
    kd, nd = sum(int(r["detected"]) for r in v), len(v)
    kf, nf = sum(int(r["detected"]) for r in s), len(s)
    pd, ld, hd = wilson(kd, nd); pf, lf, hf = wilson(kf, nf)
    per_model.append({"model": m, "detect_k": kd, "detect_n": nd, "detect_pct": round(100 * pd, 1),
                      "detect_ci_lo": round(100 * ld, 1), "detect_ci_hi": round(100 * hd, 1),
                      "fp_k": kf, "fp_n": nf, "fp_pct": round(100 * pf, 1),
                      "fp_ci_lo": round(100 * lf, 1), "fp_ci_hi": round(100 * hf, 1),
                      "discriminating": m in DISCRIMINATING})

per_class = collections.defaultdict(list)
for r in rows:
    if r["model"] in DISCRIMINATING and r["label"] == "vuln":
        per_class[r["category"]].append(int(r["detected"]))
cls = []
for cat, v in per_class.items():
    k, n = sum(v), len(v); p, lo, hi = wilson(k, n)
    cwes = sorted({r["cwe"] for r in rows if r["category"] == cat})
    cls.append({"class": CLASS_NAMES.get(cat, cat), "category": cat, "cwe": "/".join(cwes),
                "detect_k": k, "detect_n": n, "detect_pct": round(100 * p, 1),
                "ci_lo": round(100 * lo, 1), "ci_hi": round(100 * hi, 1)})
cls.sort(key=lambda x: -x["detect_pct"])

for name, data in (("summary_per_model.csv", per_model), ("summary_per_class.csv", cls)):
    with open(os.path.join(OUT, name), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(data[0].keys())); w.writeheader(); w.writerows(data)

print(f"{len(rows)} trials, {len(models)} models\n")
print("Per-model detection and false-positive rates (Wilson 95% CI)")
for r in per_model:
    tag = "" if r["discriminating"] else "  (non-discriminating)"
    print(f"  {r['model']:22s} detect {r['detect_pct']:5.1f}% [{r['detect_ci_lo']}-{r['detect_ci_hi']}]   "
          f"FP {r['fp_pct']:5.1f}% [{r['fp_ci_lo']}-{r['fp_ci_hi']}]{tag}")
print("\nPer-class detection, discriminating models pooled (Wilson 95% CI)")
for r in cls:
    print(f"  {r['class']:28s} {r['cwe']:16s} {r['detect_pct']:5.1f}% ({r['detect_k']}/{r['detect_n']}) [{r['ci_lo']}-{r['ci_hi']}]")
