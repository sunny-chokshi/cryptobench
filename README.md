# CryptoBench

[![DOI](https://zenodo.org/badge/1398425562.svg)](https://doi.org/10.5281/zenodo.23067051)


A small, controlled benchmark for one question: **when a locally run code model reviews Python, which classes of cryptographic API misuse does it catch, and which does it miss?**

CryptoBench contains 54 short Python snippets across nine misuse classes, a self-contained harness that queries models through [Ollama](https://ollama.com), and the full record of 1,890 trials across seven open code models. Every number in the accompanying paper can be regenerated from this repository with one command.

## What is in the benchmark

Nine misuse classes, mapped to CWEs. Each class has four distinct vulnerable snippets and two matched secure controls that accomplish the same task correctly, so a model that flags everything can be told apart from one that actually discriminates.

| Class | CWE | Vulnerable examples | Secure controls |
|---|---|---|---|
| Weak password hash | 328 | MD5 / SHA-1 for passwords or tokens | bcrypt, Argon2 |
| ECB mode | 327 | AES-ECB | AES-GCM, AES-CBC with random IV |
| Hardcoded key / secret | 321 | key or JWT secret as a string constant | key read from environment |
| Static / reused IV | 329 | zero or constant IV or nonce | `os.urandom` IV |
| Weak PRNG for security values | 338 | `random` for tokens, OTPs, session keys | `secrets` |
| Short asymmetric key | 326 | RSA-512 / 768 / 1024, DSA-512 | RSA-3072 / 4096 |
| Obsolete / broken cipher | 327 | DES, 3DES, RC4, Blowfish | AES-GCM, ChaCha20 |
| Unsalted / fast KDF | 759 / 916 | plain SHA-256 for passwords, 100-iteration PBKDF2 | salted PBKDF2 200k, scrypt |
| Disabled certificate verification | 295 | `verify=False`, `CERT_NONE`, unverified SSL context | default verification, pinned CA bundle |

Snippets use PyCryptodome, `cryptography`, `hashlib`, `requests`, `ssl`, and PyJWT so that a per-class result reflects the misuse rather than one library's naming. Every snippet is synthetic and self-contained: no real keys, no exploit code, nothing that runs against a live system.

The task is deliberately minimal. The model sees one snippet and a fixed instruction to answer `VERDICT: VULNERABLE` or `VERDICT: SAFE` plus a one-sentence reason. Only the verdict is scored.

## Files

```
crypto_bench.py            harness: all 54 snippets, the prompt, the Ollama call, the parser
data/snippets.jsonl        the 54 snippets as one JSON object per line
data/snippets.csv          same, as CSV
results/crypto_results.csv 1,890 trials: 54 snippets x 5 repeats x 7 models
results/summary_per_model.csv   detection and false-positive rate per model
results/summary_per_class.csv   detection rate per misuse class, discriminating models pooled
scripts/analyze.py         regenerates both summary tables from the raw trials
CITATION.cff, .zenodo.json, LICENSE
```

Columns in `results/crypto_results.csv`: `ts, model, sample_id, cwe, category, label, verdict, detected, correct, repeat, note`. `label` is `vuln` or `secure`; `detected` is 1 when the verdict was VULNERABLE; `correct` is 1 when the verdict matched the label; `note` holds the model's raw reply, truncated to 120 characters.

## Models evaluated

qwen2.5-coder at 0.5B, 1.5B, 3B, 7B and 14B (a size ladder within one family), plus deepseek-coder 6.7B and codellama 7B. All run locally through Ollama at temperature 0, five repeats per snippet. No trial errored.

## Headline results

Reproduce with `python3 scripts/analyze.py`.

**Four of the seven models are non-discriminating**: they flag most secure code as vulnerable too (false-positive rates of 68 to 93 percent), so their high detection rates mean nothing. The three that discriminate are qwen2.5-coder 7B, qwen2.5-coder 14B and deepseek-coder 6.7B.

**Detection is sharply uneven by class** (three discriminating models pooled, n = 60 per class, Wilson 95% CI):

| Class | Detected |
|---|---|
| Disabled certificate verification | 96.7% [88.6, 99.1] |
| Obsolete / broken cipher | 91.7% [81.9, 96.4] |
| ECB mode | 90.0% [79.9, 95.3] |
| Weak password hash | 81.7% [70.1, 89.4] |
| Static / reused IV | 78.3% [66.4, 86.9] |
| Short asymmetric key | 78.3% [66.4, 86.9] |
| Unsalted / fast KDF | 60.0% [47.4, 71.4] |
| Hardcoded key / secret | 58.3% [45.7, 69.9] |
| Weak PRNG for security values | 38.3% [27.1, 51.0] |

The classes at the top can be recognized by a name or token the models have seen flagged in training data (`verify=False`, `DES`, `MD5`, `MODE_ECB`). The classes at the bottom involve an ordinary, legitimate API used in the wrong place (`random.choice` for a token). Model size does not close the gap: for weak PRNG, qwen 3B, 7B and 14B catch 8, 6 and 11 of 20.

## Running it yourself

Requirements: Python 3 and a running Ollama server. No pip installs.

```bash
ollama pull qwen2.5-coder:7b
python3 crypto_bench.py --model qwen2.5-coder:7b --repeats 5
python3 scripts/analyze.py
```

Results append to `crypto_results.csv` in the working directory. Set `OLLAMA_ENDPOINT` to point at a non-default server.

## Limitations

Per-class counts are small (four snippets per class), so lean on the class ordering and the size-flatness rather than any single percentage. Everything is Python. The verdict-only protocol measures detection, not whether a model could repair the code. Models were run at default quantization and with one fixed prompt.

## Citation

Paper: S. Chokshi, "Known-Bad Names, Unknown-Bad Uses: What Local Code Models Detect When They Review Cryptographic API Misuse," 2026, manuscript.

Dataset: S. Chokshi, "CryptoBench: A benchmark of cryptographic API misuse for evaluating LLM code reviewers," v1.0.0, Zenodo, 2026. doi:10.5281/zenodo.23067052. All versions: doi:10.5281/zenodo.23067051. See also `CITATION.cff`.

## License

Code is MIT. Data and results are CC BY 4.0. See `LICENSE`.

## Author

Sunny Chokshi, University of the Cumberlands. ORCID [0009-0003-4738-7759](https://orcid.org/0009-0003-4738-7759).
