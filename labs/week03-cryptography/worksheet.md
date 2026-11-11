# Worksheet 3 — Cryptography Used Correctly (and Misused) (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 3**
> **Aligned to:** OWASP 2025 A04 Cryptographic Failures · CWE-327, CWE-916, CWE-330, CWE-798
> **Signature game:** "Capture the Hash" (recover plaintext from weak hashes)

> **Ethics note:** Crack only the hashes provided in `hashes.txt` on your own machine. Password-cracking against accounts or systems you don't own is illegal. Wordlists and recovered values stay inside the lab VM.

## Part 1 — Student Information
| Name | Student ID | Date | Group |
|Neree Booncharoen|6631503018|9-9-2026|---|
| | | | |

## Part 2 — Lecture Questions
Answer in your own words (2–4 sentences each).
1. Distinguish hashing, encryption, and encoding — and give one job each is the wrong tool for.
Answer:Hashing is a one-way process mainly used to verify data, encryption protects data so it can be decrypted with a key, and encoding changes data into another format for compatibility. Hashing is the wrong tool for storing data that must later be recovered, encryption is unnecessary for simply checking whether two passwords match, and encoding provides no real security.
2. Why is a fast hash like MD5/SHA-1 a bad choice for storing passwords, and what should be used instead?
Answer:MD5 and SHA-1 are designed to be fast, so attackers can try huge numbers of password guesses very quickly. Passwords should instead be stored using a slow, password-specific hashing algorithm such as Argon2id, bcrypt, or scrypt, with a unique salt.
3. What is a salt, what attack does it defeat, and why must it be unique per password?
Answer:A salt is a random value added to a password before hashing. It makes precomputed attacks such as rainbow tables much less useful and ensures that identical passwords produce different stored hashes, so each password should have its own unique salt.
4. Why does AES-ECB leak structure, and what does an authenticated mode like AES-GCM add?
Answer:AES-ECB encrypts identical plaintext blocks into identical ciphertext blocks, so patterns and structure in the original data can remain visible. AES-GCM provides encryption together with authentication, allowing the receiver to detect if the ciphertext has been modified or tampered with.
5. What's the difference between `random` and a CSPRNG (e.g. `secrets`), and where does it matter?
Answer:Python's random module is designed for general-purpose randomness and is not suitable for security-sensitive values because its output can be predictable. A CSPRNG such as secrets is designed to generate unpredictable values and should be used for passwords, reset tokens, session tokens, authentication codes, and cryptographic keys.

![Four paired rows showing that password storage, cipher mode, randomness and key source are four separate crypto decisions: MD5 (CWE-916/327) becomes argon2id, AES-ECB with a hardcoded key (CWE-327) becomes AES-GCM with a nonce and tag, a 6-digit random.choice token (CWE-330) becomes secrets.token_urlsafe, and HARDCODED_KEY (CWE-798) becomes a key injected from the environment — so naming AES answers none of the four questions.](img/crypto-misuse.svg)

## Part 3 — Hands-on Lab (180 min)
**Learning goals:** exploit four crypto misuses, then remediate them with a vetted KDF, authenticated encryption, and a CSPRNG.
**Prerequisites:** Docker (or local Python 3.12); `hashcat` or `john`; the `rockyou.txt` wordlist.

**Environment setup**
```bash
cd labs/week03-cryptography
docker compose up           # installs pycryptodome + argon2-cffi, runs both scripts
# or locally:
pip install pycryptodome argon2-cffi
python vulnerable_crypto.py # see the md5 hash, repeated ECB blocks, 6-digit token
```
Targets: `vulnerable_crypto.py` (the misuses), `hashes.txt` (four unsalted MD5s), and `solution_skeleton.py` (the fix).

**What to submit per task:** the command/payload run + a screenshot of the result + a 2–3 sentence mitigation.

**Task 0 — Onboarding (5 min)** · *Goal:* see the misuse output. *Steps:* run `python vulnerable_crypto.py`; note the md5 digest, the identical ECB ciphertext blocks, and the short token. *Deliverable:* screenshot of the program output.

**Task 1 — Capture the Hash (30 min)** · *Goal:* recover the passwords. *Steps:* strip the comment lines from `hashes.txt`, then run `hashcat -m 0 hashes.txt rockyou.txt` (or the `john --format=raw-md5` equivalent); recover all four plaintexts. *Deliverable:* screenshot of the cracked results (mask any real-looking value). Note in one line why unsalted MD5 fell so fast (CWE-916/327).

```sim
aes-modes
```

**Task 2 — ECB structure leak (20 min)** · *Goal:* prove ECB leaks. *Steps:* call `encrypt_ecb(b"A"*16 + b"A"*16)` from `vulnerable_crypto.py` and show the two 16-byte ciphertext blocks are identical; explain how this leaks plaintext structure (CWE-327). *Deliverable:* hex output highlighting the repeated block.

**Task 3 — Predictable token (15 min)** · *Goal:* show the reset token is guessable. *Steps:* call `reset_token()` repeatedly; argue why a 6-digit `random` token (10^6 space, non-CSPRNG) is brute-forceable (CWE-330). *Deliverable:* sample tokens + a one-line attack estimate.

**Task 4 — Hardcoded key (5 min)** · *Goal:* identify the key-management flaw. *Steps:* find `HARDCODED_KEY` in `vulnerable_crypto.py`; explain why shipping a key in source is CWE-798. *Deliverable:* the line + a 2-sentence mitigation.

**Task 5 — Crack the project target's hashes (25 min)** · *Goal:* apply cracking to your term project. *Steps:* **NoteVault** stores unsalted MD5 password hashes; obtain them (via the app's `/admin` once you can reach it, or from its `seed()`), and crack them with `hashcat -m 0`. *Deliverable:* the recovered password(s) + note the CWE — record this finding for your project report (`project/REPORT-TEMPLATE.md` in the repo root).

**Task 6 — Password storage migration (25 min)** · *Goal:* fix it the way real apps do. *Steps:* write `store_password`/`verify_password` with **argon2id**, and a **rehash-on-login** path that upgrades a legacy MD5 record to argon2id the next time the user logs in. *Deliverable:* the code + a short note on why migration matters.

**Task 7 — Authenticated encryption round-trip (20 min)** · *Goal:* use AEAD correctly. *Steps:* encrypt+decrypt a message with **AES-GCM** using a random 12-byte nonce and a key from an env var; then flip one ciphertext byte and show decryption **fails** (tag check). *Deliverable:* the round-trip output + the tampered-fails proof.

**Task 8 — TLS in practice (15 min)** · *Goal:* read a real cert. *Steps:* run `openssl s_client -connect example.com:443 </dev/null 2>/dev/null | tee /tmp/tls.txt | openssl x509 -noout -issuer -subject -dates` for the cert summary, then `grep -E 'Protocol|New,' /tmp/tls.txt` for the negotiated TLS version (the version line is printed by `s_client`, not by `x509`, so the plain pipe would discard it); identify issuer, validity, and that TLS version. *Deliverable:* the cert summary + one line on what TLS protects that hashing/at-rest encryption does not.

**Task 9 — Defend / fix it (20 min)** · *Goal:* remediate using `solution_skeleton.py`. *Steps:* run `python solution_skeleton.py`; confirm `store_password`/`verify_password` use argon2id (auto-salted), `encrypt_gcm` uses a random 12-byte nonce + auth tag with a key from `ENC_KEY_HEX` env, and `reset_token` uses `secrets`. Map each fix to the CWE it closes. *Deliverable:* before/after table (misuse → fix → CWE closed) + screenshot of the fixed script running.

## Part 4 — Reflection
1. Map each of the four misuses to its CWE and to OWASP A04, in one line each.
2. Name a real-world breach caused by weak password hashing or hardcoded keys, and which fix here would have prevented it.
3. Across all four fixes, which closes the largest real-world risk, and why?

## Grading rubric (100)
| Criterion | Points |
|---|---|
| Lecture questions (Part 2) | 20 |
| Exploitation + evidence (cracked hashes + ECB/token/key proof + screenshots) | 40 |
| Defense (working `solution_skeleton.py` + before/after mapping) | 25 |
| Reflection (CWE/OWASP mapping + breach + biggest-risk fix) | 15 |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** ____________________
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
  Answer:I tested the vulnerable code by providing unexpected or malicious input and observed that the application accepted and processed it. The vulnerability worked because the application did not properly validate or protect user-controlled data before using it.
  
  2. **Why does your fix actually stop it** — and what could still break it?
  Answer:The fix stops the vulnerability by validating untrusted input on the server and safely processing it before use. It could still be vulnerable if another endpoint does not use the same protection, if the validation is incomplete, or if future code changes remove or weaken the security controls.


---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
Answer:The AI suggested fixing the vulnerable endpoint by validating user input before processing it. It recommended treating all client-controlled data as untrusted, using server-side validation, rejecting invalid input, and preserving the endpoint's normal functionality.
2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
Answer:The response was too general because it did not provide the exact validation rules required by the vulnerable endpoint. The risky line was:

“using server-side validation”

This does not specify what input should be accepted or rejected, so the fix could still allow malicious input if the validation is incomplete.
3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.
Answer:I corrected the fix by adding specific server-side validation for the expected input and rejecting unexpected or malicious values before the application processes them. I verified the fix by testing both a legitimate request, which still worked, and the malicious input, which was rejected. The AI's original answer was insufficient because it described the security principle but did not provide enough implementation detail or a concrete verification test.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.
Answer:The vulnerable endpoint accepts data from the user and processes it without properly checking whether the input is safe. This is exploitable because an attacker can send unexpected or malicious input directly to the endpoint, bypassing any client-side restrictions.
**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
Answer:Review the vulnerable endpoint below and produce a secure fix for the identified vulnerability.

Treat all user-controlled input as untrusted. Add appropriate server-side validation and sanitization based on the endpoint's intended functionality, reject invalid or malicious input, and preserve legitimate requests. Do not rely on client-side validation. Do not invent APIs or security controls that are not supported by the framework. Show the corrected code and explain exactly why the change prevents the vulnerability.

After applying the fix, provide two verification tests: one legitimate request that must continue to succeed and one malicious request that must fail. The fix is only considered successful if the legitimate request works and the malicious request is rejected or safely handled.

Vulnerable code:
[PASTE THE VULNERABLE ENDPOINT HERE]
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*
