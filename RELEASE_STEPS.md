# Publishing CryptoBench: GitHub -> Zenodo -> Hugging Face

Do these in order. Zenodo mints the DOI from the GitHub release, and the
Hugging Face card then links to both.

## 1. GitHub (about 10 minutes)

1. Create a new PUBLIC repository named `cryptobench` under your GitHub account.
   Do not initialize it with a README.
2. In Terminal, from this folder:

       cd /Users/sc/Documents/RP/1_CURRENT_PAPERS/08_NetCrypt_CryptoMisuse/CryptoBench_release
       git init
       git add .
       git commit -m "CryptoBench v1.0.0: 54 snippets, 1,890 trials, 7 models"
       git branch -M main
       git remote add origin https://github.com/<your-username>/cryptobench.git
       git push -u origin main

3. Confirm the README renders on the repo page.

## 2. Zenodo (about 5 minutes)

1. Log in to zenodo.org with your ORCID (already set up).
2. Go to your account menu -> GitHub. Click "Sync now", then flip the switch
   ON next to `cryptobench`.
3. Back on GitHub: Releases -> "Draft a new release".
   Tag: `v1.0.0`   Title: `CryptoBench v1.0.0`
   Description: paste the first paragraph of README.md. Click Publish release.
4. Within a few minutes Zenodo creates the record automatically from
   `.zenodo.json` and mints a DOI. Copy the DOI.
5. Paste the DOI into README.md under "Citation", commit, push. (Zenodo
   makes a new version for each release; that is fine.)

## 3. Hugging Face (about 5 minutes)

1. Create an account at huggingface.co (use ucumberlands.edu email, add
   your ORCID in the profile).
2. New -> Dataset. Name: `cryptobench`. Public. License: cc-by-4.0.
3. Upload these three files from the `huggingface/` folder:
   `README.md`, `snippets.jsonl`, `crypto_results.csv`.
4. Edit README.md on Hugging Face to add the GitHub link and the Zenodo DOI
   where it says "to be added".

## 4. Record it

- Add the Zenodo DOI to ORCID Works (Add work -> DOI).
- Send Claude the DOI and the two URLs to log in the planner.

## What NOT to upload

The `code/` folder still holds `crypto_bench.py` (the pilot) and
`crypto_results.csv` (the pilot's results, which include a comment-injection
condition the paper excludes). Those stay private. Only the
`CryptoBench_release` folder goes public.
