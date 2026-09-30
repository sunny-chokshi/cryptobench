---
license: cc-by-4.0
language:
  - en
task_categories:
  - text-classification
tags:
  - code
  - security
  - cryptography
  - vulnerability-detection
  - cwe
  - llm-evaluation
  - python
pretty_name: CryptoBench
size_categories:
  - n<1K
configs:
  - config_name: snippets
    data_files: snippets.jsonl
  - config_name: results
    data_files: crypto_results.jsonl
---

# CryptoBench

A controlled benchmark for measuring which classes of **cryptographic API misuse** a code-reviewing language model catches, and which it misses.

- **54 Python snippets** across nine misuse classes: 36 vulnerable, 18 matched secure controls that do the same task correctly.
- **1,890 recorded trials**: every snippet, 5 repeats, 7 open code models run locally through Ollama at temperature 0.
- **Verdict-only protocol**: the model answers `VERDICT: VULNERABLE` or `VERDICT: SAFE` with a one-sentence reason.

## Misuse classes

| Class | CWE |
|---|---|
| Weak password hash (MD5 / SHA-1) | 328 |
| ECB mode | 327 |
| Hardcoded key or secret | 321 |
| Static or reused IV / nonce | 329 |
| Weak PRNG for security values | 338 |
| Short asymmetric key | 326 |
| Obsolete / broken cipher (DES, RC4, Blowfish) | 327 |
| Unsalted or fast KDF | 759 / 916 |
| Disabled certificate verification | 295 |

## Configs

**`snippets`** (`snippets.jsonl`): `id`, `cwe`, `category`, `label` (`vuln` or `secure`), `code`.

**`results`** (`crypto_results.jsonl`): `ts`, `model`, `sample_id`, `cwe`, `category`, `label`, `verdict`, `detected`, `correct`, `repeat`, `note`.

## Models in the results

qwen2.5-coder 0.5B / 1.5B / 3B / 7B / 14B, deepseek-coder 6.7B, codellama 7B.

## Key finding

Four of seven models flag nearly all code as vulnerable and are non-discriminating. Among the three that discriminate (qwen2.5-coder 7B and 14B, deepseek-coder 6.7B), detection ranges from 96.7% for disabled certificate verification down to 38.3% for weak PRNG used for security tokens. Misuse that carries a known-bad name (`DES`, `MD5`, `verify=False`) is caught; misuse that is an ordinary API in the wrong place is not, and larger models do not close the gap.

## Harness and reproduction

The harness and analysis script live in the companion GitHub repository: https://github.com/sunny-chokshi/cryptobench `python3 scripts/analyze.py` regenerates every number above with Wilson 95% intervals.

## Safety

All snippets are synthetic. No real credentials, no exploit code, nothing that touches a live system.

## Citation

S. Chokshi, "Known-Bad Names, Unknown-Bad Uses: What Local Code Models Detect When They Review Cryptographic API Misuse," 2026, manuscript. Dataset: CryptoBench v1.0.0, Zenodo, 2026. doi:10.5281/zenodo.23067052

Author: Sunny Chokshi, University of the Cumberlands. ORCID 0009-0003-4738-7759.
