# Worksheet 2 — Secure SDLC & Tooling (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 2**
> **Aligned to:** OWASP 2025 (A05 Injection [CWE-89, CWE-78], A04 Cryptographic Failures [CWE-327], A02 Security Misconfiguration [CWE-798, CWE-489]) · CWE-798, CWE-89, CWE-78, CWE-327, CWE-489
> **Signature game:** "Bug Triage Race" (scan → triage; score = true positives − misclassified)

> **Ethics note:** The scanners run only against the provided `vulnerable-repo/` on your own machine. Do not point SAST/secret scanners at third-party repos or production systems without authorization. Treat any secret you find here as fake lab data.

## Part 1 — Student Information
| Name | Student ID | Date | Group |
|Neree Booncharoen|6631503018|9-9-2026|---|

## Part 2 — Lecture Questions
Answer in your own words (2–4 sentences each).
1. Distinguish SAST, DAST, and SCA — what does each see, and when in the SDLC does each run?
Answer:SAST analyzes source code without running the application, so it is usually used during development and CI. DAST tests the running application from the outside, typically in testing/staging, while SCA checks third-party libraries and dependencies for known vulnerabilities and license issues.
2. What is secret scanning, and why do hardcoded secrets keep ending up in repos?
Answer:Secret scanning searches code, commits, and sometimes configuration files for exposed credentials such as API keys, passwords, and tokens. Hardcoded secrets often end up in repositories because developers put credentials directly in code or configuration for convenience and accidentally commit them.
3. What does "shift-left / DevSecOps" mean in practice for a CI pipeline?
Answer:It means bringing security checks earlier into the software development process instead of waiting until the final testing stage. In a CI pipeline, this can include SAST, SCA, secret scanning, tests, and other security checks automatically running on every pull request or build.
4. Why is coverage-guided fuzzing considered the dominant modern bug-finding technique?
Answer:Coverage-guided fuzzing generates many different inputs and uses code coverage feedback to focus on inputs that reach new program paths. This makes it effective at automatically exploring complex code and finding crashes, memory bugs, and unexpected behavior that manual testing may miss.
5. Define true positive vs. false positive in scanner triage, and why misclassifying both directions is costly.
Answer:A true positive is a scanner finding that correctly identifies a real security issue, while a false positive reports a problem that is not actually exploitable or relevant. Missing a true issue wastes security opportunities, while treating too many false positives as real creates alert fatigue and wastes developer time.

![A left to right SDLC pipeline showing SAST at write code, secret scanning at commit, SCA and fuzzing at build, and DAST at deploy, with what each tool cannot see written underneath it.](img/sdlc-gates.svg)

## Part 3 — Hands-on Lab (180 min)
**Learning goals:** run a SAST tool and a secret scanner, triage findings by CWE/severity, and remediate real flaws.
**Prerequisites:** Docker installed; internet to pull the Semgrep/Gitleaks images.

**Environment setup**
```bash
cd labs/week02-sdlc-tooling
cat scan.sh                 # see exactly what it runs
bash scan.sh                # Semgrep (p/default + p/owasp-top-ten) then Gitleaks on ./vulnerable-repo
```
Target under scan: `vulnerable-repo/app.py` (plus `requirements.txt`). It contains five planted flaws.

**What to submit per task:** the command/payload run + a screenshot of the finding + a 2–3 sentence mitigation.

**Task 0 — Onboarding (5 min)** · *Goal:* confirm tooling. *Steps:* run `bash scan.sh`; confirm both Semgrep and Gitleaks sections produce output. *Deliverable:* screenshot showing both tools ran.

**Task 1 — SAST sweep with Semgrep (25 min)** · *Goal:* find code flaws. *Steps:* read the Semgrep output; locate the SQL injection in `/user` (CWE-89, string-formatted query), the OS command injection in `/ping` (CWE-78, `shell=True`), the weak `md5` password hash (CWE-327), and `debug=True` (CWE-489). *Deliverable:* one screenshot per finding with the file:line.

**Task 2 — Secret scan with Gitleaks (15 min)** · *Goal:* find leaked credentials. *Steps:* read the Gitleaks output; identify `AWS_SECRET_ACCESS_KEY` and `DB_PASSWORD` (CWE-798). *Deliverable:* screenshot + the rule that fired for each.

**Task 3 — Bug Triage Race (30 min)** · *Goal:* triage accurately. *Steps:* build a table with columns *Tool | File:Line | CWE | Severity | TP/FP | Fix idea*; mark at least 3 true positives and 1 likely false positive and justify each. (Score = TP − misclassified.) *Deliverable:* the completed triage table.

**Task 4 — Fuzzing intro (10 min)** · *Goal:* see coverage-guided fuzzing find a bug SAST won't. *Steps:* in the `labs/toolbox` container (Apple clang has no libFuzzer runtime), build `clang -g -fsanitize=address,fuzzer harness.c -o fuzz`, then **seed the corpus** and run it:
`mkdir -p corpus && printf 'FUZ' > corpus/seed && ./fuzz corpus`. It crashes almost immediately with an AddressSanitizer heap-buffer-overflow at `harness.c:23` (the `data[3]` read with no `size > 3` check). Seeding matters: an unseeded `./fuzz` has to rediscover the magic bytes by chance and often finds nothing for minutes — that unpredictability is itself worth a sentence in your write-up. (The deep fuzzing+exploit lab is Week 11.) *Deliverable:* the ASan crash output (or a screenshot) + a 2-sentence note on why fuzzing finds this bug when a linter/SAST pass over the same 4-line check would not.

**Task 5 — Scan the project target (40 min)** · *Goal:* apply the tools to your term project. *Steps:* run Semgrep + Gitleaks against **NoteVault** (`../../project/starter-app`); also run an SCA scan: `docker run --rm -v "$PWD/../../project/starter-app:/src" aquasec/trivy fs /src`. *Deliverable:* a findings list (tool, file:line/CVE, CWE) — reuse it in your project vuln report.

**Task 6 — Build a security CI gate (25 min)** · *Goal:* automate the scan (previews Week 15). *Steps:* adapt `../week15-devsecops-pipeline/security-ci.yml` into a workflow that runs Semgrep + Trivy + Gitleaks and **fails on HIGH/CRITICAL**; run it locally (`act`) or commit to your fork and read the Actions log. *Deliverable:* the workflow file + a screenshot of a failing run.

**Task 7 — SAST blind spots (20 min)** · *Goal:* see what scanners miss. *Steps:* find one real bug in `vulnerable-repo/app.py` (or NoteVault) that Semgrep did **not** flag, and explain why a pattern-based tool missed it. *Deliverable:* the bug + a 2-sentence explanation.

**Task 8 — Defend / fix it (10 min)** · *Goal:* remediate the planted flaws in `vulnerable-repo/app.py`. *Steps:* rewrite `/user` to use a parameterized query (`?` placeholder); remove `shell=True` and pass an argument list in `/ping`; move both secrets to environment variables; replace `md5` with bcrypt/argon2; set `debug=False`. *Deliverable:* a before/after diff for each fix mapped to its CWE.

## Part 4 — Reflection
1. Map two of your findings to their CWE and to the matching OWASP 2025 category.
Answer:Hardcoded API key/password → CWE-798: Use of Hard-coded Credentials → OWASP 2025 A07: Identification and Authentication Failures.
SQL injection → CWE-89: Improper Neutralization of Special Elements used in an SQL Command → OWASP 2025 A05: Injection.
2. Name a real-world breach caused by a hardcoded/leaked secret or an injection flaw, and what control would have caught it pre-release.
Answer:The 2017 Equifax breach involved an unpatched vulnerability rather than a hardcoded secret, so a better injection example is the 2021 MOVEit Transfer attacks, which exploited SQL injection. A pre-release DAST/SAST security test could have helped identify the injection vulnerability before deployment, while proper input validation and parameterized queries would mitigate it in the application.
3. Which single tool (SAST vs. secret scanning) gave the highest-value findings on this repo, and why?
Answer:For this repo, secret scanning would give the highest-value findings if it identified actual credentials or tokens committed to the code. These findings are especially important because a leaked secret can provide direct access to systems, whereas SAST may produce more findings that require manual review to determine whether they are exploitable.

## Grading rubric (100)
| Criterion | Points |
|---|---|
| Lecture questions (Part 2) | 20 |
| Exploitation + evidence (scan output + triage table + screenshots) | 40 |
| Defense (remediated `app.py` with before/after diffs) | 25 |
| Reflection (CWE/OWASP mapping + breach + tool value) | 15 |

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
  Answer:"I tested the vulnerable endpoint by sending unexpected or malicious input. The vulnerability worked because the application trusted user-controlled data without properly validating it on the server, allowing the input to be processed in an unsafe way.
  2. **Why does your fix actually stop it** — and what could still break it?
  Answer:The fix stops the attack by treating all user input as untrusted and validating it on the server before processing it. However, the vulnerability could still exist if another endpoint does not apply the same validation, if the validation is incomplete, or if future code changes weaken or remove the security checks.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
Answer:A common fix for XSS is to sanitize user input before displaying it. For example, if a Flask application receives a comment, you can use the html library:
2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
Answer:The risky part is:

"Then store safe_comment in the database and display it on the page."

This is incomplete because escaping should normally happen at the output/context where the data is rendered, rather than permanently storing HTML-escaped data. Also, html.escape() is appropriate for HTML text contexts but does not automatically make input safe for every context, such as JavaScript, CSS, URLs, or HTML attributes.

Another incomplete part is:

"script-src 'self'"

A Content Security Policy can reduce the impact of XSS, but it does not replace proper output encoding. A CSP also needs to match the application's actual resource requirements; simply adding script-src 'self' is not enough to claim that the application is completely protected against XSS.
3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.
Answer:A safer Flask/Jinja2 implementation is:

from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/comment", methods=["POST"])
def comment():
    comment = request.form["comment"]
    return render_template("comment.html", comment=comment)

comment.html:

<p>{{ comment }}</p>

Jinja2 autoescapes variables in normal HTML templates, so characters such as < and > are encoded instead of being interpreted as HTML/JavaScript. The AI's answer was insufficient because it treated input sanitization and CSP as a complete solution, while the correct defense depends on context-appropriate output encoding; CSP should be used as an additional defense-in-depth control.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.
Answer:The vulnerable endpoint accepts data from the user and uses it without properly checking whether the data is trustworthy. An attacker can take advantage of this because input coming from outside the application crosses a trust boundary, but the application treats it as if it were safe, allowing unintended or malicious data to affect the application's behavior.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
Answer:Review the vulnerable Flask endpoint provided below and fix the identified trust-boundary vulnerability securely.

Requirements:

Treat all data received from the client as untrusted.
Validate and sanitize user-controlled input on the server side before using or storing it.
Do not rely on client-side validation.
Preserve the endpoint's intended legitimate functionality.
Do not introduce a new vulnerability while fixing it.
Use the existing framework and libraries where possible; do not invent APIs or functions.
Show the exact vulnerable code, the corrected code, and briefly explain why the fix prevents the attack.
After proposing the fix, provide a concrete verification test that should fail against the attack case but still succeed for a normal legitimate request.

 
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*
