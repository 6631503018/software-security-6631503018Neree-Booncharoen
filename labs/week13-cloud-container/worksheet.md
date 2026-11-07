# Worksheet 13 — Cloud & Container Security (4 hrs)

> **Course:** Software Security (KOSEN69) · Week 13
> **Aligned to:** OWASP 2025 **A02 Security Misconfiguration** · **CWE-732** (incorrect permission assignment), **CWE-16** (configuration), plus CWE-798, CWE-250, CWE-538, CWE-269, CWE-1104
> **Signature game:** 🔍 *Misconfig Hunt* (CloudGoat-style) — each misconfig you find **and** fix = a flag.

> ⚠️ **Ethics note:** All artifacts here are deliberately broken for teaching and are marked *"Sandbox/teaching only; for authorized lab use."* Scan, exploit, and harden **only** these lab files (or systems you own / are authorized to test). Never point Trivy or these techniques at third-party cloud accounts or images without written permission.

---

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|Neree Booncharoen|6631503018|------|-------|
|      |           |      |       |

---

## Part 2 — Lecture Questions

Answer in your own words (2–4 sentences each).

1. Explain the **shared-responsibility model**. In `harden.md` it says "the cloud provider secures *of* the cloud; you secure what you put *in* it." Give one concrete example of each side for an S3-backed app.
Answer The shared-responsibility model means the cloud provider secures the cloud infrastructure, while the customer secures the applications and data they put in the cloud. For an S3-backed app, AWS secures the physical servers and storage infrastructure, while the developer must configure S3 bucket permissions correctly and prevent unauthorized access to uploaded files.
2. `iam-policy-insecure.json` uses `"Action": "*"` and `"Resource": "*"`. Describe **why this violates least privilege** and map it to CWE-732 vs CWE-269 — what is the difference between the two CWEs here?
Answer Using "Action": "*" and "Resource": "*" grants access to all actions and resources, violating least privilege. CWE-732 refers to incorrect permissions on critical resources, while CWE-269 refers to improper privilege management.
3. The insecure Dockerfile bakes `ENV API_TOKEN=sk_live_...`. Explain how an attacker recovers that secret from a shipped image (name the `docker` commands) and why this is **CWE-798 / CWE-200**.
Answer An attacker can use docker pull, docker inspect, and docker history --no-trunc to investigate an image and potentially recover a hardcoded API token. This is CWE-798 because the secret is hardcoded, and CWE-200 because sensitive information is exposed to unauthorized users.
4. Why is `FROM python:latest` (CWE-1104/CWE-16) a security and reproducibility problem, and how does pinning to an `@sha256:` digest fix it?
AnswerUsing FROM python:latest is risky because the image can change over time, introducing vulnerabilities or breaking reproducible builds. Pinning the image to an @sha256: digest ensures that the exact same image content is used for each build.
5. What does a **distroless** base image remove (relative to `python:3.11-slim`), and how does that shrink the attack surface for an RCE or container-escape attacker?
Answer
---

## Part 3 — Hands-on Lab (180 min)

**Learning goals:** find cloud/container misconfigurations with Trivy, map each to a CWE, and rebuild the IAM policy + Dockerfile to least privilege / hardened so the findings drop.

**Prerequisites:** Docker installed and running; the `week13-cloud-container/` lab folder; internet access to pull `aquasec/trivy:latest`.

### Environment setup (real commands)

```bash
cd labs/week13-cloud-container

# Option A — the provided wrapper (trivy config over the Dockerfiles; IAM JSON is reviewed manually, see Task 2):
bash scan.sh

# Option B — run Trivy directly (MEDIUM is in the filter on purpose: one of the
# three rules Task 1 asks you to cite is rated MEDIUM, and HIGH,CRITICAL hides it):
docker run --rm -v "$PWD:/src" aquasec/trivy:latest config --severity MEDIUM,HIGH,CRITICAL /src

# (Optional) build + CVE-scan the hardened image:
docker build -f Dockerfile.hardened -t week13-hardened:lab .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --severity HIGH,CRITICAL week13-hardened:lab
```

**What to submit per task:** the command(s) you ran + the relevant output (finding count or the specific finding line), a screenshot of the Trivy/terminal result, and a 2–3 sentence mitigation explaining *why* the fix reduces risk (cite the CWE).

![The same app shipped as two stacked container images, Dockerfile.insecure beside Dockerfile.hardened, with each layer paired to its fix and its CWE, and only the unpinned :latest tag, the root user and the ENV secret marked as things trivy config actually flags.](img/container-hardening.svg)

### Tasks

- **Task 0 — Onboarding (15 min).** Confirm Docker works (`docker version`), run `bash scan.sh`, and record the **baseline finding count** against `Dockerfile.insecure` (Trivy's `config` scanner does not parse standalone IAM policy JSON, so `iam-policy-insecure.json` is reviewed manually instead — see Task 2). **Deliverable:** screenshot of the baseline scan.

- **Task 1 — Misconfig Hunt: container image (40 min).** *Goal:* find every defect in `Dockerfile.insecure`. *Steps:* read each `# DEFECT:` comment, then locate the matching Trivy finding where one exists — only 3 of the 6 (unpinned `:latest`, runs as root, secrets in `ENV`) map to a Trivy config rule (`DS-0001`, `DS-0002`, `DS-0031`); `COPY . .`, `chmod -R 777`, and unpinned `pip install` are instruction-level RUN/COPY semantics Trivy's Dockerfile scanner doesn't check, so identify those 3 by code review instead. Build a table: defect → CWE → Trivy rule/severity (write "manual review — no Trivy rule" where none exists). *Deliverable:* completed table (6 rows) using the IDs from `harden.md`.

- **Task 2 — Misconfig Hunt: IAM (30 min).** *Goal:* document why `iam-policy-insecure.json` is full-admin. *Steps:* identify the `Action:*` / `Resource:*` / no-`Condition` problems; map to CWE-269 / CWE-732. *Deliverable:* 3-row table + one sentence on the blast radius if these creds leak.

- **Task 3 — Secrets & storage (25 min).** *Goal:* show secrets must not live in the image. *Steps:* explain how `ENV API_TOKEN` / `AWS_SECRET_ACCESS_KEY` are exposed via `docker history`; propose where they belong instead (secrets manager / mounted secret / orchestrator secret per `harden.md`). *Deliverable:* 2–3 sentence remediation + the `.dockerignore` entries you would add to stop `COPY . .` leaking `.git`/`.env` (CWE-538).

- **Task 4 — Hardened-Dockerfile + least-priv-IAM defense (50 min).** *Goal:* prove the "after" is clean. *Steps:* (a) re-run `bash scan.sh` (or `trivy config`) against `Dockerfile.hardened` and capture the **reduced** finding count (Trivy's config scanner does not parse standalone IAM JSON, so confirm the IAM fix manually per Task 2 by diffing `iam-policy-leastpriv.json` against the insecure policy); (b) for the Dockerfile, point to the fix for each Task-1 defect (digest pin, multi-stage venv, distroless runtime, `USER 65532:65532`, no secrets in `ENV`, copy only `app.py`); (c) for IAM, confirm the rewrite scopes `s3:GetObject` to `arn:aws:s3:::lab-app-bucket/app/*` and adds the `s3:prefix` `Condition`; (d) list the extra runtime flags from `harden.md` (`--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`). *Deliverable:* before/after finding counts, the defect→fix mapping, and the diffed policy/Dockerfile with one sentence per fix.

- **Task 5 — Flag tally (20 min).** *Goal:* score the hunt. *Steps:* one flag per misconfig found **and** fixed (6 container + 3 IAM = 9). *Deliverable:* flag count + the single biggest-risk misconfig and why.

---

## Part 4 — Reflection

1. **Mapping.** For three findings, write the line of the artifact → CWE → OWASP 2025 A02, and the one-line fix.
Answer:The mapping should connect the vulnerable artifact (where the problem was found), its CWE classification, the OWASP 2025 category, and the fix.
Finding	Artifact → CWE	OWASP 2025	One-line fix
F-01: Over-permissive IAM	IAM policy → CWE-250 (Execution with Unnecessary Privileges)	A02: Security Misconfiguration	Apply least-privilege IAM permissions and remove unnecessary access.
F-02: Running container as root	Dockerfile → CWE-250 (Execution with Unnecessary Privileges)	A02: Security Misconfiguration	Run the container as a non-root user.
F-03: Unnecessary packages in container	Dockerfile → CWE-1104 (Use of Unmaintained Third Party Components)	A02: Security Misconfiguration	Use a minimal, maintained distroless image to reduce the attack surface.
2. **Real incident.** Briefly describe a real breach caused by a cloud/container misconfiguration (e.g., a public S3 bucket leak, or an over-permissive IAM role). What single control from this lab would have prevented it?
Answer:Incident: Capital One suffered a major data breach in 2019, exposing information belonging to approximately 100 million customers and applicants.

What happened:
1. An attacker exploited a misconfiguration in a web application firewall (WAF).
2. The attacker accessed AWS instance metadata and obtained temporary IAM credentials.
3. The IAM role had excessive permissions to access S3 storage.
4. The attacker used those permissions to access sensitive customer information. 
   DOI+2
Single control that could have limited the breach:

Least-privilege IAM.

If the WAF's IAM role had only the permissions it actually needed, compromising that role would not have provided broad access to sensitive S3 data.
3. **Best mitigation.** Of everything you did, which control gives the most risk reduction per unit of effort, and why? Argue for least-privilege IAM vs. distroless+non-root.
Answer:believe least-privilege IAM provides the greatest risk reduction per unit of effort for this lab.
Comparison	Least-privilege IAM	Distroless + Non-root
Main protection	Limits cloud resource access	Reduces container attack surface
Security benefit	Limits unauthorized data access	Limits available tools and privileges
Implementation	Restrict IAM policies and permissions	Change base image and user
Impact	Reduces potential breach damage	Reduces container exploitation risk
---

## Grading rubric (100)

| Component | Points | What earns full marks |
|-----------|:------:|-----------------------|
| Part 2 — Lecture questions | 20 | All 5 answered correctly with CWE/A02 reasoning |
| Part 3 — Tasks + evidence | 40 | Tasks 0–5 complete; commands, outputs, and screenshots present |
| Defense (Task 4 hardening) | 25 | Hardened Dockerfile + least-priv IAM shown to reduce findings; per-fix justification |
| Part 4 — Reflection | 15 | Accurate mapping, relevant incident, well-argued best mitigation |

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
   Answer:

I tested the insecure configuration and found that it had too many permissions and weak security settings. The vulnerability worked because the system allowed more access than necessary, so an attacker could access things they should not be able to access.
  2. **Why does your fix actually stop it** — and what could still break it?
Answer:I fixed it by giving only the permissions that the system really needs. I also changed the container to run as a non-root user and used a distroless image to make it more secure.

These changes make it harder for attackers to cause damage. However, the system could still have problems if the permissions are set incorrectly or if there are other vulnerabilities in the application.
---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
Answer:asked an AI assistant how to fix the security problems in my Docker and cloud configuration.

The AI suggested:
- Use least-privilege IAM policies instead of giving too many permissions.
- Run Docker containers as a non-root user.
- Use distroless images to reduce unnecessary packages.
- Remove unnecessary permissions and configurations to improve security.
2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
Answer:The AI answer was too general and did not show the exact changes needed in the configuration files.

For example:
- "Use least-privilege IAM policies" does not explain which permissions should be removed.
- "Run Docker containers as a non-root user" does not specify the user in the Dockerfile.
- "Use distroless images" does not explain whether the application can still run correctly.
The AI answer also did not include testing results to prove that the fixes actually work.
3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.
Answer:I fixed the configuration by changing the IAM policy to allow only the permissions required by the application. I also updated the Dockerfile to use a distroless image and run the application as a non-root user.

The AI answer was insufficient because it only gave general suggestions without showing the actual implementation. My solution is better because I applied the changes to the configuration files and checked that the application could still run.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.
Answer:The vulnerable configuration gives the application more permissions than it actually needs. If an attacker gains access to the application, they may also access other cloud resources because the permissions are not properly restricted. This makes the system more dangerous if something goes wrong.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
Answer:I have a Docker and cloud security configuration with excessive IAM permissions. Please review the insecure configuration and fix it.

Requirements:

Follow the principle of least privilege.

Give the application only the permissions it really needs.

Do not use wildcard permissions such as * unless absolutely necessary.

Update the Dockerfile to use a non-root user.

Use a minimal distroless image where compatible with the application.

Keep the application working correctly.

Explain every change and why it improves security.

Do not invent APIs, permissions, or configuration options.

Provide the corrected configuration and explain how to test that the security fixes work.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*
