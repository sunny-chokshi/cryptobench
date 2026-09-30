#!/usr/bin/env python3
"""CryptoBench. Can a local LLM code reviewer detect cryptographic
API misuse, per misuse class? Four distinct vuln snippets per class + matched
secure controls, so each per-class claim rests on real n (not one snippet).

Pure crypto-misuse domain. No comment-injection, no false-positive framing as a
contribution - this instrument backs a single paper contribution: the per-class
detectability profile of local code models across the size range.

Self-contained: Python 3 + Ollama only. No pip installs.

Usage
-----
  python3 crypto_bench.py --model qwen2.5-coder:7b --repeats 2
Results append to crypto_results.csv:
  ts,model,sample_id,cwe,category,label,verdict,detected,correct,repeat,note
"""
import argparse, csv, json, os, time, urllib.request

OLLAMA = os.environ.get("OLLAMA_ENDPOINT", "http://127.0.0.1:11434/api/chat")

SYS = ("You are a security code reviewer. Examine the code and decide whether it "
       "contains a security vulnerability. Reply with exactly one line in this format:\n"
       "VERDICT: VULNERABLE  or  VERDICT: SAFE\n"
       "Then, on a second line, give a one-sentence reason. Do not output anything else.")

def V(id, cwe, cat, code): return dict(id=id, cwe=cwe, category=cat, label="vuln", code=code)
def S(id, cwe, cat, code): return dict(id=id, cwe=cwe, category=cat, label="secure", code=code)

SAMPLES = [
 # ================= weak / broken hash for passwords (CWE-328) =================
 V("wh_md5pw","CWE-328","weak_hash",'import hashlib\ndef store_password(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n'),
 V("wh_sha1pw","CWE-328","weak_hash",'import hashlib\ndef hash_pw(pw):\n    return hashlib.sha1(pw.encode()).hexdigest()\n'),
 V("wh_md5tok","CWE-328","weak_hash",'import hashlib\ndef api_token(user_id):\n    return hashlib.md5(str(user_id).encode()).hexdigest()\n'),
 V("wh_sha1sig","CWE-328","weak_hash",'import hashlib\ndef sign(msg, key):\n    return hashlib.sha1(key + msg).hexdigest()\n'),
 S("wh_bcrypt","CWE-328","weak_hash",'import bcrypt\ndef store_password(pw):\n    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())\n'),
 S("wh_argon","CWE-328","weak_hash",'from argon2 import PasswordHasher\nph = PasswordHasher()\ndef store_password(pw):\n    return ph.hash(pw)\n'),

 # ================= ECB mode (CWE-327) =================
 V("ecb_aes","CWE-327","ecb_mode",'from Crypto.Cipher import AES\ndef enc(key, data):\n    c = AES.new(key, AES.MODE_ECB)\n    return c.encrypt(data)\n'),
 V("ecb_aes2","CWE-327","ecb_mode",'from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\ndef enc(key, data):\n    c = Cipher(algorithms.AES(key), modes.ECB())\n    e = c.encryptor()\n    return e.update(data) + e.finalize()\n'),
 V("ecb_field","CWE-327","ecb_mode",'from Crypto.Cipher import AES\ndef encrypt_ssn(key, ssn):\n    return AES.new(key, AES.MODE_ECB).encrypt(ssn.ljust(16).encode())\n'),
 V("ecb_loop","CWE-327","ecb_mode",'from Crypto.Cipher import AES\ndef enc_blocks(key, blocks):\n    c = AES.new(key, AES.MODE_ECB)\n    return [c.encrypt(b) for b in blocks]\n'),
 S("ecb_gcm","CWE-327","ecb_mode",'import os\nfrom Crypto.Cipher import AES\ndef enc(key, data):\n    nonce = os.urandom(12)\n    c = AES.new(key, AES.MODE_GCM, nonce=nonce)\n    ct, tag = c.encrypt_and_digest(data)\n    return nonce, ct, tag\n'),
 S("ecb_cbc","CWE-327","ecb_mode",'import os\nfrom Crypto.Cipher import AES\ndef enc(key, data):\n    iv = os.urandom(16)\n    return iv, AES.new(key, AES.MODE_CBC, iv).encrypt(data)\n'),

 # ================= hardcoded key / secret (CWE-321) =================
 V("hk_aes","CWE-321","hardcoded_key",'from Crypto.Cipher import AES\nKEY = b"0123456789abcdef"\ndef enc(data, iv):\n    return AES.new(KEY, AES.MODE_CBC, iv).encrypt(data)\n'),
 V("hk_hmac","CWE-321","hardcoded_key",'import hmac, hashlib\nSECRET = b"s3cr3t_signing_key"\ndef sign(msg):\n    return hmac.new(SECRET, msg, hashlib.sha256).hexdigest()\n'),
 V("hk_jwt","CWE-321","hardcoded_key",'import jwt\nJWT_SECRET = "my-hardcoded-jwt-secret"\ndef make_token(uid):\n    return jwt.encode({"uid": uid}, JWT_SECRET, algorithm="HS256")\n'),
 V("hk_fernet","CWE-321","hardcoded_key",'from cryptography.fernet import Fernet\nKEY = b"dGhpc19pc19hX2hhcmRjb2RlZF9rZXlfMTIzND0="\ndef enc(data):\n    return Fernet(KEY).encrypt(data)\n'),
 S("hk_env","CWE-321","hardcoded_key",'import os\nfrom Crypto.Cipher import AES\ndef enc(data, iv):\n    key = os.environ["AES_KEY"].encode()\n    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)\n'),
 S("hk_env2","CWE-321","hardcoded_key",'import os, hmac, hashlib\ndef sign(msg):\n    secret = os.environ["SIGNING_KEY"].encode()\n    return hmac.new(secret, msg, hashlib.sha256).hexdigest()\n'),

 # ================= static / zero / reused IV or nonce (CWE-329) =================
 V("iv_zero","CWE-329","static_iv",'from Crypto.Cipher import AES\nIV = b"\\x00" * 16\ndef enc(key, data):\n    return AES.new(key, AES.MODE_CBC, IV).encrypt(data)\n'),
 V("iv_const","CWE-329","static_iv",'from Crypto.Cipher import AES\nIV = b"1234567890abcdef"\ndef enc(key, data):\n    return AES.new(key, AES.MODE_CFB, IV).encrypt(data)\n'),
 V("iv_nonce","CWE-329","static_iv",'from Crypto.Cipher import AES\nNONCE = b"000000000000"\ndef enc(key, data):\n    c = AES.new(key, AES.MODE_GCM, nonce=NONCE)\n    return c.encrypt(data)\n'),
 V("iv_reuse","CWE-329","static_iv",'from Crypto.Cipher import AES\ndef enc(key, data, iv=b"\\x11"*16):\n    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)\n'),
 S("iv_rand","CWE-329","static_iv",'import os\nfrom Crypto.Cipher import AES\ndef enc(key, data):\n    iv = os.urandom(16)\n    return iv, AES.new(key, AES.MODE_CBC, iv).encrypt(data)\n'),
 S("iv_rand2","CWE-329","static_iv",'import os\nfrom Crypto.Cipher import AES\ndef enc(key, data):\n    nonce = os.urandom(12)\n    c = AES.new(key, AES.MODE_GCM, nonce=nonce)\n    return nonce, c.encrypt(data)\n'),

 # ================= weak PRNG for security tokens (CWE-338) =================
 V("pr_token","CWE-338","weak_prng",'import random\ndef make_token(n=16):\n    return "".join(random.choice("0123456789abcdef") for _ in range(n))\n'),
 V("pr_otp","CWE-338","weak_prng",'import random\ndef generate_otp():\n    return random.randint(100000, 999999)\n'),
 V("pr_reset","CWE-338","weak_prng",'import random, string\ndef reset_token():\n    return "".join(random.choices(string.ascii_letters, k=32))\n'),
 V("pr_seed","CWE-338","weak_prng",'import random, time\ndef session_key():\n    random.seed(time.time())\n    return random.getrandbits(128)\n'),
 S("pr_secrets","CWE-338","weak_prng",'import secrets\ndef make_token(n=16):\n    return secrets.token_hex(n)\n'),
 S("pr_secrets2","CWE-338","weak_prng",'import secrets\ndef reset_token():\n    return secrets.token_urlsafe(32)\n'),

 # ================= inadequate asymmetric key size (CWE-326) =================
 V("sk_rsa512","CWE-326","short_key",'from Crypto.PublicKey import RSA\ndef gen():\n    return RSA.generate(512)\n'),
 V("sk_rsa1024","CWE-326","short_key",'from Crypto.PublicKey import RSA\ndef gen():\n    return RSA.generate(1024)\n'),
 V("sk_dsa","CWE-326","short_key",'from Crypto.PublicKey import DSA\ndef gen():\n    return DSA.generate(512)\n'),
 V("sk_rsa768","CWE-326","short_key",'from cryptography.hazmat.primitives.asymmetric import rsa\ndef gen():\n    return rsa.generate_private_key(public_exponent=65537, key_size=768)\n'),
 S("sk_rsa3072","CWE-326","short_key",'from Crypto.PublicKey import RSA\ndef gen():\n    return RSA.generate(3072)\n'),
 S("sk_rsa4096","CWE-326","short_key",'from cryptography.hazmat.primitives.asymmetric import rsa\ndef gen():\n    return rsa.generate_private_key(public_exponent=65537, key_size=4096)\n'),

 # ================= broken / obsolete cipher (CWE-327) =================
 V("bc_des","CWE-327","broken_cipher",'from Crypto.Cipher import DES\ndef enc(key, data):\n    return DES.new(key, DES.MODE_ECB).encrypt(data)\n'),
 V("bc_3des","CWE-327","broken_cipher",'from Crypto.Cipher import DES3\ndef enc(key, data, iv):\n    return DES3.new(key, DES3.MODE_CBC, iv).encrypt(data)\n'),
 V("bc_rc4","CWE-327","broken_cipher",'from Crypto.Cipher import ARC4\ndef enc(key, data):\n    return ARC4.new(key).encrypt(data)\n'),
 V("bc_blowfish","CWE-327","broken_cipher",'from Crypto.Cipher import Blowfish\ndef enc(key, data, iv):\n    return Blowfish.new(key, Blowfish.MODE_CBC, iv).encrypt(data)\n'),
 S("bc_aesgcm","CWE-327","broken_cipher",'import os\nfrom Crypto.Cipher import AES\ndef enc(key, data):\n    n = os.urandom(12)\n    return n, AES.new(key, AES.MODE_GCM, nonce=n).encrypt(data)\n'),
 S("bc_chacha","CWE-327","broken_cipher",'import os\nfrom Crypto.Cipher import ChaCha20\ndef enc(key, data):\n    n = os.urandom(12)\n    return n, ChaCha20.new(key=key, nonce=n).encrypt(data)\n'),

 # ================= no salt / fast KDF for passwords (CWE-759/916) =================
 V("ns_sha256","CWE-759","no_salt",'import hashlib\ndef derive(pw):\n    return hashlib.sha256(pw.encode()).hexdigest()\n'),
 V("ns_md5","CWE-759","no_salt",'import hashlib\ndef derive(pw):\n    return hashlib.md5(pw.encode()).digest()\n'),
 V("ns_lowiter","CWE-916","no_salt",'import hashlib\ndef derive(pw, salt):\n    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 100)\n'),
 V("ns_double","CWE-759","no_salt",'import hashlib\ndef derive(pw):\n    return hashlib.sha256(hashlib.sha256(pw.encode()).digest()).hexdigest()\n'),
 S("ns_pbkdf2","CWE-759","no_salt",'import os, hashlib\ndef derive(pw):\n    salt = os.urandom(16)\n    return salt, hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200000)\n'),
 S("ns_scrypt","CWE-759","no_salt",'import os, hashlib\ndef derive(pw):\n    salt = os.urandom(16)\n    return salt, hashlib.scrypt(pw.encode(), salt=salt, n=16384, r=8, p=1)\n'),

 # ================= disabled certificate / TLS verification (CWE-295) =================
 V("cv_verifyfalse","CWE-295","cert_verify",'import requests\ndef fetch(url):\n    return requests.get(url, verify=False).text\n'),
 V("cv_sslctx","CWE-295","cert_verify",'import ssl, urllib.request\ndef fetch(url):\n    ctx = ssl._create_unverified_context()\n    return urllib.request.urlopen(url, context=ctx).read()\n'),
 V("cv_certnone","CWE-295","cert_verify",'import ssl\ndef ctx():\n    c = ssl.create_default_context()\n    c.check_hostname = False\n    c.verify_mode = ssl.CERT_NONE\n    return c\n'),
 V("cv_session","CWE-295","cert_verify",'import requests\ndef client():\n    s = requests.Session()\n    s.verify = False\n    return s\n'),
 S("cv_verifytrue","CWE-295","cert_verify",'import requests\ndef fetch(url):\n    return requests.get(url).text\n'),
 S("cv_pinned","CWE-295","cert_verify",'import requests\ndef fetch(url):\n    return requests.get(url, verify="/etc/ssl/ca-bundle.pem").text\n'),
]

def ask(model, code):
    body = {"model": model, "stream": False,
            "messages": [{"role": "system", "content": SYS},
                         {"role": "user", "content": "Review this code:\n\n" + code}]}
    req = urllib.request.Request(OLLAMA, data=json.dumps(body).encode(),
                                 headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=150) as r:
        out = json.loads(r.read().decode())
    return out["message"]["content"] if "message" in out else out["choices"][0]["message"]["content"]

def parse_verdict(txt):
    up = txt.upper()
    for line in up.splitlines():
        line = line.strip()
        if line.startswith("VERDICT:"):
            if "VULNERABLE" in line: return "VULNERABLE"
            if "SAFE" in line: return "SAFE"
    if "VULNERABLE" in up and "SAFE" not in up: return "VULNERABLE"
    if "SAFE" in up and "VULNERABLE" not in up: return "SAFE"
    if "VULNERABLE" in up: return "VULNERABLE"
    if "SAFE" in up: return "SAFE"
    return "UNCLEAR"

def run_one(model, s):
    try:
        txt = ask(model, s["code"])
    except Exception as e:
        return {"verdict": "ERR", "detected": 0, "correct": 0, "note": ("ERR:" + str(e))[:120]}
    v = parse_verdict(txt)
    detected = 1 if v == "VULNERABLE" else 0
    correct = (1 if v == "VULNERABLE" else 0) if s["label"] == "vuln" else (1 if v == "SAFE" else 0)
    return {"verdict": v, "detected": detected, "correct": correct, "note": txt.replace("\n", " ")[:120]}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--repeats", type=int, default=2)
    a = ap.parse_args()
    new = not os.path.exists("crypto_results.csv")
    f = open("crypto_results.csv", "a", newline="")
    w = csv.writer(f)
    if new:
        w.writerow(["ts","model","sample_id","cwe","category","label",
                    "verdict","detected","correct","repeat","note"])
    t0 = time.time()
    for s in SAMPLES:
        for rep in range(a.repeats):
            r = run_one(a.model, s)
            w.writerow([int(time.time()), a.model, s["id"], s["cwe"], s["category"],
                        s["label"], r["verdict"], r["detected"], r["correct"], rep, r["note"]])
            f.flush()
            print(f"[{a.model}] {s['id']:16} {s['label']:6} rep{rep} -> {r['verdict']:10} ok={r['correct']}", flush=True)
    f.close()
    print(f"done {a.model}  ({(time.time()-t0)/60:.1f} min)", flush=True)

if __name__ == "__main__":
    main()
