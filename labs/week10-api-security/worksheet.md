# Worksheet 10 — API Security (3 hrs)

> **Course:** Software Security (KOSEN69) · Week 10
> **Aligned:** OWASP API Security Top 10:2023 — API1 BOLA · API3 Broken Object Property Level Auth (Mass Assignment) · API4 Unrestricted Resource Consumption
> **Signature game:** 🥷 crAPI Raid
>
> **Ethics note:** Run exploits **only** against the lab targets shipped here (`vulnerable_api.py` on `:8080`) or your own OWASP crAPI instance. Never test BOLA, mass assignment, or brute-force against systems you do not own or are not explicitly authorized to test.

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|Neree Booncharoen|6631503018|------|-------|
|      |           |      |       |

## Part 2 — Lecture Questions

1. Define **BOLA (API1:2023)**. Why is it the #1 API risk, and why can't a WAF reliably stop it?
Answer:BOLA (Broken Object Level Authorization) occurs when an API fails to check whether a user has permission to access a specific object. For example, a user can change an ID in a request to view another user's private information. It is ranked as the #1 API risk because it can expose sensitive data or allow unauthorized actions. A WAF cannot reliably stop BOLA because the request may look normal, and the WAF usually does not know whether the user is authorized to access that particular object.
2. What is **mass assignment / broken object property level authorization (API3:2023)**? Contrast a blocklist vs. an allow-list of bindable fields.
Answer:Mass assignment occurs when an API automatically accepts user-supplied fields that should not be controlled by the user, such as isAdmin or accountBalance. A blocklist rejects specific dangerous fields but may miss new or unexpected fields. An allow-list accepts only explicitly approved fields, making it safer because unauthorized properties cannot be modified through the request.
3. **API4:2023** is unrestricted resource consumption. Give two distinct impacts (security and availability) of an unthrottled `/api/login`.
Answer:-Security impact: Attackers can perform brute-force attacks using many password attempts, increasing the risk of account compromise.
-Availability impact: Excessive login requests can consume server resources, slow down the API, or cause a denial-of-service condition that prevents legitimate users from logging in.
4. In `vulnerable_api.py`, `current_user()` trusts the `X-User-Id` header. Why is a client-supplied header NOT authentication, and what should replace it?
Answer:A client-supplied X-User-Id header is not authentication because users can modify the header and impersonate another user without proving their identity. It should be replaced with verified authentication, such as a server-validated session cookie or a signed access token, such as a JWT. The server must validate the user's identity and then check their permissions for each requested resource.
5. Why does object-level authorization have to be checked **per request, per object** rather than once at login?
Answer:A successful login only proves the user's identity; it does not grant permission to access every object in the system. Different objects may belong to different users or have different access rules, and permissions may change over time. Therefore, the server must check authorization on every request for each specific object to prevent unauthorized access or modification.

## Part 3 — Hands-on Lab (145 min)

**Learning goals:** Exploit BOLA, mass assignment, and a missing rate limit against a live API; then read the secure version and explain each fix.

**Prerequisites:** Docker + Docker Compose, `curl`. (Optional bonus: cloned OWASP crAPI.)

**Environment setup**
```bash
cd labs/week10-api-security
docker compose up         # INSECURE API on :8080, SECURE API on :8081
# Seeded users: alice(id 1) bob(id 2) carol(id 3, admin, balance 9999)
```

**What to submit per task:** the exact command(s) + raw response/HTTP status, a screenshot, and a 2–3 sentence mitigation note mapping the bug to its OWASP API id.

### Task 0 — Onboarding (15 min)
Confirm both APIs respond: `curl http://localhost:8080/` and `curl http://localhost:8081/`. Note which port is insecure. Record the three seeded users.
**Deliverable:** both root responses + the user table.

![One REST API with three flaws — reading another user's orders by id, smuggling an admin field into user creation, and an unthrottled login — each shown at the handler where it occurs, next to its one-line fix.](img/api-flaws.svg)

### Task 1 — BOLA: read another user's orders (35 min)
**Goal:** Read carol's (admin) orders without being carol — API1:2023.
**Steps:**
1. `curl http://localhost:8080/api/users/3/orders` — note you receive the "Server rack" order with no auth.
![alt text](image.png)
2. Iterate the id: `curl http://localhost:8080/api/users/2/orders`.
![alt text](image-1.png)
3. On the secure API observe the ladder: `curl -i http://localhost:8081/api/users/3/orders` (401), `curl -i -H "X-User-Id: 1" http://localhost:8081/api/users/3/orders` (403), `curl -i -H "X-User-Id: 1" http://localhost:8081/api/users/1/orders` (200).
**Deliverable:** the leaked order JSON + the 401/403/200 transcript + mitigation note.
![alt text](image-2.png),![alt text](image-3.png),![alt text](image-4.png)
The insecure API allows users to access another user's orders by changing the user ID in the URL. The request to /api/users/3/orders returned HTTP 200 OK and exposed Carol's order containing the item Server rack and the demo flag.

To mitigate this API1:2023 Broken Object Level Authorization (BOLA) vulnerability, the API must authenticate the caller and verify object ownership or administrator permissions before returning order data. The secure API returns HTTP 401 for unauthenticated requests, HTTP 403 for unauthorized access, and HTTP 200 for authorized access.
### Task 2 — Mass assignment: self-promote to admin (30 min)
**Goal:** Smuggle `is_admin` + `balance` into user creation — API3:2023.
**Steps:**
1. `curl -X POST http://localhost:8080/api/users -H "Content-Type: application/json" -d '{"username":"mallory","password":"x","is_admin":true,"balance":1000000}'`
![alt text](image-5.png)
2. Confirm the response echoes `"is_admin": true, "balance": 1000000`.
![alt text](image-6.png) ,The insecure API accepts user-controlled properties during account creation by merging the entire JSON request body into the new user object. This allows a client to set privileged fields such as is_admin and balance, resulting in unauthorized privilege escalation.

The vulnerability is mitigated by using an allow-list (ALLOWED_CREATE_FIELDS) in solution_api.py to accept only permitted fields. Sensitive properties such as administrator privileges and account balance must be controlled by the server, not by client input.
3. Repeat against `:8081` and confirm the smuggled fields are forced to `is_admin:false, balance:0`.
**Deliverable:** both responses side by side + mitigation note (allow-list in `solution_api.py`).
![alt text](image-7.png)

### Task 3 — Unrestricted resource consumption: brute-force login (25 min)
**Goal:** Show `/api/login` has no throttle — API4:2023.
**Steps:**
1. Run the brute-force loop from `attack.md` against `:8080` (guesses incl. `alice123`) — all attempts processed.
![alt text](image-8.png)![alt text](image-9.png)![alt text](image-10.png) The insecure API processes repeated login attempts without rate limiting, increasing the risk of brute-force attacks. This maps to API4:2023 Unrestricted Resource Consumption.

The secure API implements a rate limiter that allows five login attempts within a 60-second window and returns HTTP 429 when the limit is exceeded. This reduces repeated password guessing and helps protect the authentication endpoint from excessive requests.
2. On `:8081` loop 7 times: `for i in $(seq 1 7); do curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8081/api/login -H "Content-Type: application/json" -d '{"username":"alice","password":"wrong"}'; done`
![alt text](image-11.png)The insecure API processes repeated login attempts without rate limiting, allowing repeated password guesses and increasing the risk of brute-force attacks. This vulnerability maps to API4:2023 Unrestricted Resource Consumption.

The secure API implements a rate limiter that allows five login attempts within a 60-second window and returns HTTP 429 when the limit is exceeded. This helps prevent excessive requests and reduces the risk of repeated password guessing.
3. Confirm the 6th/7th attempt returns `429`.
**Deliverable:** the `401 401 401 401 401 429 429` sequence + mitigation note.
![alt text](image-12.png) The insecure API allows repeated login attempts without rate limiting, increasing the risk of brute-force attacks. This vulnerability maps to API4:2023 Unrestricted Resource Consumption.

The secure API limits login attempts to five within a 60-second window and returns HTTP 429 when the limit is exceeded. This helps reduce repeated password guessing and excessive requests.

### Task 4 — Bonus: crAPI Raid (optional, 20 min)
Against your own OWASP crAPI instance (`git clone https://github.com/OWASP/crAPI.git`), capture one BOLA or mass-assignment flag.
**Deliverable:** flag + endpoint + which API Top 10 id it maps to.
Flag: Not obtained yet
Endpoint: /identity/api/v2/vehicle/{vehicleid}/location
OWASP API Top 10 ID: API1:2023 — Broken Object Level Authorization (BOLA)
![alt text](image-14.png) ![alt text](image-15.png)


### Task 5 — Defend / fix it (20 min)
**Goal:** Explain the fixes using the secure reference `solution_api.py`.
**Steps:** Read the three `# --- FIX ...` blocks. For each, quote the line(s) that defeat your Task 1–3 exploit: the per-object ownership check (`caller["id"] != uid and not caller["is_admin"]`), `ALLOWED_CREATE_FIELDS` binding, and the `RATE_LIMIT=5 / RATE_WINDOW=60` limiter.
**Deliverable:** for each of API1/API3/API4 — the exploit that worked on `:8080`, the line in `solution_api.py` that blocks it, and the new HTTP status on `:8081`.
1. API1 — Broken Object Level Authorization (BOLA)

Exploit on :8080: Accessing another user's object without proper ownership validation.

Fix in solution_api.py: if caller["id"] != uid and not caller["is_admin"]:
How it works: The API checks whether the caller owns the requested object or is an administrator. Unauthorized access is denied.
HTTP status on :8081: 403 Forbidden (expected; verify against the actual response).
2. API3 — Broken Object Property Level Authorization
Exploit on :8080: Supplying unauthorized or privileged properties when creating an object.
Fix in solution_api.py: ALLOWED_CREATE_FIELDS binding.
How it works: The API accepts only explicitly allowed fields, preventing users from setting protected properties through mass assignment.
HTTP status on :8081: 400 Bad Request (expected; verify against the actual response).
3. API4 — Unrestricted Resource Consumption
Exploit on :8080: Sending repeated requests without an effective rate limit.
Fix in solution_api.py: RATE_LIMIT = 5 and RATE_WINDOW = 60.
How it works: The API limits requests to 5 within a 60-second window.
HTTP status on :8081: 429 Too Many Requests when the rate limit is exceeded.
## Part 4 — Reflection

1. **Mapping:** complete a table — finding | endpoint | OWASP API id | fix applied.
Answer :finding | endpoint | OWASP API id | fix applied.
Unauthorized access to another user's object (BOLA)	Object-specific endpoint on :8080	API1:2023	Check ownership using caller["id"] != uid and not caller["is_admin"]
Unauthorized modification of protected fields (mass assignment)	Object-creation endpoint on :8080	API3:2023	Bind input to ALLOWED_CREATE_FIELDS
Excessive requests / resource consumption	Rate-limited endpoint on :8080	API4:2023	Apply RATE_LIMIT = 5 and RATE_WINDOW = 60
2. **Real breach:** research an API authorization breach (e.g., the Optus or T-Mobile BOLA/IDOR incidents). Which API Top 10 id matches, and would the `solution_api.py` ownership check have prevented it?
Answer :In 2023, T-Mobile reported that an attacker accessed customer information through an API. Approximately 37 million customer accounts were affected.
This incident is related to API security because customer data was accessed without authorization. It may be mapped to API1:2023 (Broken Object Level Authorization), although public information does not confirm that BOLA was the exact cause of the incident.
The ownership check in solution_api.py could have prevented unauthorized access if the vulnerability involved accessing individual customer records without checking ownership. However, it would not necessarily have prevented the entire breach because the actual attack may have involved different weaknesses.
3. **Best mitigation:** of object-level auth, allow-list binding, and rate limiting — which gives the most risk reduction for an API platform, and why?
Answer :I think object-level authorization provides the greatest risk reduction because it prevents users from accessing data that does not belong to them. If an API does not check ownership properly, an attacker may be able to access private information even when they are logged in.

Allow-list binding is also important because it prevents users from changing protected fields, such as roles or permissions. Rate limiting helps reduce excessive requests and resource exhaustion, but it cannot prevent unauthorized data access by itself.

Therefore, I would prioritize object-level authorization first, while still applying all three controls together. Each control protects against a different type of risk, and using them together provides stronger API security.

## Grading rubric (100)

| Criterion | Weight |
|-----------|--------|
| Lecture questions (Part 2) | 20 |
| Exploitation + evidence (Tasks 1–4: commands, output, screenshots) | 40 |
| Defense (Task 5: fixes mapped to `solution_api.py`) | 25 |
| Reflection (Part 4: mapping, breach, best mitigation) | 15 |
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
  2. **Why does your fix actually stop it** — and what could still break it?

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
Answer:The AI suggested that the fixed API would return 403 Forbidden, 400 Bad Request, and 429 Too Many Requests. However, these status codes were only expected examples and were not verified against the actual implementation. The AI also used a generic endpoint instead of confirming the exact endpoint in the lab code.
2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
Answer:The correct fix must be based on the actual implementation in solution_api.py. For API1, the server should verify that the caller owns the requested object or has administrator privileges. For API3, it should accept only explicitly allowed fields. For API4, it should enforce the configured rate limit. The HTTP status codes must be confirmed by testing the fixed API on port 8081.
3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.
Answer:The AI explained the intended security controls correctly, but it assumed HTTP status codes without testing them. A secure-looking code snippet is not enough; I must inspect the implementation and run the same test against the fixed API to verify that the exploit fails.
> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.
Answer:The vulnerable API does not properly check whether a user is allowed to access or modify a particular resource. This allows a user to perform actions beyond their permissions by changing request parameters or submitting unauthorized fields. The fix adds server-side authorization checks, restricts accepted fields, and limits repeated requests.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
Answer:Review the API1 vulnerability in my local training application's source code. Identify the exact vulnerable endpoint and explain the root cause. Propose a minimal secure fix that checks authentication, verifies object ownership on every request, and allows administrator access only when explicitly authorized. Preserve existing legitimate behavior, deny access by default, and avoid trusting user-supplied object IDs. Provide a focused code patch and tests for both authorized and unauthorized users. Do not invent function names or endpoints; use only the provided source code. Explain any remaining edge cases and how to verify the fix against the local fixed API on port 8081.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*
