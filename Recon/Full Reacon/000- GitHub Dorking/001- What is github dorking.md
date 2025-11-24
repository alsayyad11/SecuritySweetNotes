
## Introduction

GitHub can be a goldmine for bug bounty hunters, but also a minefield if used carelessly. Developers often commit code, scripts, examples, and sometimes accidentally leave sensitive information inside repositories. What you find on GitHub can range from harmless snippets to critical secrets that provide direct access to production systems.

The danger comes from the privileges of what’s exposed. Even a single API key or token with wide permissions can give access to cloud servers, databases, or pipelines that can deploy code. A minor leak can become a major security incident.

This guide will teach you **where to look, how to search efficiently using GitHub dorks, and how to safely verify and report findings**.

---

## What to Look For (General)

When exploring GitHub, focus on files or information that are sensitive or shouldn't be public:

* **Configuration files:** `.env`, `config.*`, `settings.*`
* **Keys & tokens:** `API_KEY`, `AWS_ACCESS_KEY_ID`, `Authorization: Bearer …`
* **CI/CD workflows:** `.github/workflows/*`
* **SSH keys / .pem files** that were accidentally committed
* **Customer or employee sensitive data (PII)**
* **Database connection strings:** `postgres://`, `mysql://`, `mongodb+srv://`
* Anything else the company wouldn’t want public

---

## GitHub Dorks: Powerful Search Queries

GitHub’s search engine allows you to use specific queries (“dorks”) to locate sensitive data. Below are categorized examples. Replace `org_name_in_github` with your target’s GitHub organization.

### Emails

```text
org:(org_name_in_github) "@gmail.com"
org:(org_name_in_github) "@yahoo.com"
org:(org_name_in_github) "@hotmail.com"
org:(org_name_in_github) "@(target_company_email)"
```

### Tokens / Secrets / API Keys

```text
org:(org_name_in_github) "AWS_SECRET_ACCESS_KEY"
org:(org_name_in_github) "AWS_ACCESS_KEY_ID"
org:(org_name_in_github) "Authorization: Bearer"
org:(org_name_in_github) "api_key" language:json
org:(org_name_in_github) "secret" language:yaml
org:(org_name_in_github) "PRIVATE_KEY"
org:(org_name_in_github) "Token"
org:(org_name_in_github) "client_secret"
org:(org_name_in_github) "password" language:env
org:(org_name_in_github) filename:.env
org:(org_name_in_github) filename:.npmrc
org:(org_name_in_github) filename:.dockercfg
org:(org_name_in_github) filename:.bash_history
org:(org_name_in_github) "BEGIN RSA PRIVATE KEY"
```

### Config Files

```text
org:(org_name_in_github) filename:config.js
org:(org_name_in_github) filename:settings.py
org:(org_name_in_github) filename:application.properties
org:(org_name_in_github) filename:credentials.json
org:(org_name_in_github) filename:firebase.json
```

### GitHub Actions

```text
org:(org_name_in_github) filename:.github/workflows
org:(org_name_in_github) "secrets." language:yaml
org:(org_name_in_github) "GITHUB_TOKEN"
org:(org_name_in_github) "CI_SECRET"
```

### Hardcoded Credentials (Inside Code)

```text
org:(org_name_in_github) "username" "password"
org:(org_name_in_github) "db_password"
org:(org_name_in_github) "mongodb+srv://"
org:(org_name_in_github) "postgres://"
org:(org_name_in_github) "mysql://"
```

### Admin Panels / Login URLs

```text
org:(org_name_in_github) "admin"
org:(org_name_in_github) "admin" in:url
org:(org_name_in_github) "admin" in:path
org:(org_name_in_github) "dashboard" in:url
org:(org_name_in_github) "control panel"
org:(org_name_in_github) "login" filename:config.js
org:(org_name_in_github) "admin_url"
org:(org_name_in_github) "site_url"
```

> These dorks are not exhaustive — adapt them as needed, but they show the mindset of targeting sensitive data and endpoints.

---

## Tips for Successful GitHub Recon

### 1. Check the Scope First

Always confirm the bug bounty program’s scope. Many companies **do not accept GitHub-based reports** if the repo is outside their organization or the program scope.

### 2. Focus on the Company Organization

Search inside the target company’s GitHub org. Avoid external or contractor repositories unless clearly in scope.

### 3. Avoid Examples / Test Repos

If the repo looks like an example, demo, or local setup, it’s often ignored by triagers (marked as NA).
Watch for:

* Folders like `examples/`, `sandbox/`, `docs/examples/`
* README/docs phrases: “sample/test project” or “for demo purposes only”
* Keywords in repo name: `test`, `example`, `dummy`, `sample`, `demo`, `local`

### 4. Check History Before Reporting

Old commits or inactive repos may contain outdated credentials. Verify relevance before reporting.

### 5. Verify Carefully

Use **non-destructive verification**. Do not experiment on sensitive production systems. If unsure, submit a responsible report without testing.

### 6. Be Careful With Repeated Secrets

Secrets repeated across many repos are usually placeholders or examples. Focus on **unique, production-looking secrets**.

---

## Practical Scenario: Step-by-Step

Here’s an example workflow from real GitHub bug hunting:

1. **Start with the org search:**

   ```text
   org:company "password"
   ```

   Scroll through repositories and note anything that looks relevant.

2. **Open promising repos:**
   Open in new tabs to review carefully.

3. **Follow safety tips:**
   Avoid example/demo repos, check repo history, confirm it's production or active.

4. **Analyze the repository:**
   Tools like **ChatGPT** and **Grok** help understand the repo’s purpose and context.

5. **Identify sensitive data:**
   Look for hardcoded credentials, API keys, tokens, or config files.

6. **Report responsibly:**
   Once verified, submit to the bug bounty program. Include **full context**, such as repo name, file paths, type of secret, and verification steps.

**Example Finding:**

* **Type:** Hardcoded credentials (exposed in public repo)
* **Impact:** Critical — allowed the company to fix sensitive exposure immediately

> Using this methodology, researchers have found multiple high-impact issues in large organizations like HP, IBM, Stanford University, and private programs.

---

## Conclusion

GitHub dorking is an **extremely powerful tool** for bug bounty hunters. By knowing **what to look for, how to search effectively, and how to verify findings safely**, you can discover high-impact security issues that are otherwise hidden.

Remember:

* Always check scope and repo ownership
* Avoid demo or test data
* Verify safely before reporting
* Focus on unique, production-level secrets

Mastering GitHub dorking can give you **direct access to critical vulnerabilities** while remaining safe, legal, and ethical.
