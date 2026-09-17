# js-dragon
A fast, colorful JavaScript static analysis tool written in Go. It scans local files, directories, remote JS URLs, or crawls entire websites to detect exposed secrets, credentials, tokens, endpoints, dangerous sinks/sources, and vulnerable patterns.

---


## Features

- Four scan modes:
  - Single local JS file
  - Entire local directory (recursive, concurrent)
  - Single remote JS file by URL
  - Full website crawl (extracts `<script src>` and any `.js` references, then scans each file)
- Detects:
  - **API keys**: Google (`AIza...`), AWS (`AKIA...`), Stripe (`sk_live_`, `pk_live_`, `sk_test_`), GitHub (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`), Slack (`xox[baprs]-`), JWT, Bearer tokens, and generic `api_key` / `secret_key` / `access_key` / `private_key` assignments.
  - **Credentials**: passwords, usernames, DB passwords, AWS secret access keys, client secrets, Basic auth headers, and MongoDB / MySQL / PostgreSQL / Redis connection strings.
  - **Tokens**: `token`, `csrf_token`, `auth_token`, `session_id`, `jwt`.
  - **Endpoints**: absolute HTTP(S) and WebSocket URLs, relative API paths, `fetch(...)`, `axios.get/post/...`, `XMLHttpRequest.open(...)`, and `$.ajax({url: ...})`.
  - **Sinks** (dangerous write points): `innerHTML`, `outerHTML`, `document.write`, `eval`, `Function`, `setTimeout/setInterval` with string args, `insertAdjacentHTML`, `dangerouslySetInnerHTML`, `location.*`, `postMessage`, `javascript:` URLs.
  - **Sources** (tainted inputs): `location.hash/search/href`, `document.URL/referrer/cookie`, `localStorage`, `sessionStorage`, `URLSearchParams`, `window.name`, `postMessage`.
  - **Vulnerable patterns**: `new Function(...)`, string-concatenated `document.write`, `innerHTML` with `+`, `child_process`, unvalidated `exec`/`spawn`, `deserialize`/`unserialize`, `Math.random()` for security-sensitive use.
- Severity tagging (HIGH / MEDIUM / LOW) with color-coded output.
- Deduplicated findings to reduce false positives.
- Concurrent directory scans and concurrent crawl fetches.
- Optional report export to a text file.
- Supports `.js`, `.mjs`, `.cjs`, `.jsx`, and `.ts` files.

---

## Requirements

- Go 1.20 or newer
- Internet access (only for `-u` and `-s` modes)

---

## Installation

```
 go install github.com/unvalidor/js-dragon@latest
```


### Alternative: run without building

```bash
go run js-dragon.go -f app.js
```

---

## Usage

```
js-dragon [options]
```

### Flags

| Flag | Description |
|------|-------------|
| `-f <file>`   | Scan a single local JavaScript file. |
| `-d <dir>`    | Recursively scan all JS/TS files inside a directory. |
| `-u <url>`    | Scan a single remote JavaScript file by URL. |
| `-s <site>`   | Crawl a website, extract its JS files, and scan each one. |
| `-o <file>`   | Save the report to a text file. |
| `-h`          | Show help. |

---

## Examples

### Scan a single local file

```bash
./js-dragon -f ./static/app.js
```

### Scan an entire directory (recursive)

```bash
./js-dragon -d ./frontend/src
```

### Scan a remote JS file

```bash
./js-dragon -u https://example.com/static/main.js
```

### Crawl a website and scan all JS files

```bash
./js-dragon -s https://example.com
```

### Save the report to a file

```bash
./js-dragon -s https://example.com -o report.txt
```

### Combined

```bash
./js-dragon -d ./dist -o scan-results.txt
```

---

## Sample Output

```
========================================================
                    SCAN RESULTS
========================================================

API_KEY [2]
  [HIGH] ./static/app.js:42
      AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
      const firebaseKey = "AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

  [HIGH] ./static/app.js:88
      sk_live_51Hxxxxxxxxxxxxxxxxxxxxxxxxxxxx
      stripe.setKey("sk_live_51Hxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

TOKEN [1]
  [HIGH] ./static/app.js:120
      eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
      const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";

VULNERABLE [1]
  [MEDIUM] ./static/app.js:200
      eval(
      eval(userInput);

ENDPOINT [3]
  [LOW] ./static/app.js:11
      /api/v1/users
      fetch("/api/v1/users")

  [LOW] ./static/app.js:15
      https://api.example.com/data
      axios.get("https://api.example.com/data")

  [LOW] ./static/app.js:22
      wss://example.com/socket
      new WebSocket("wss://example.com/socket");

========================================================
[*] total findings: 7
========================================================
```

Findings are grouped by category (API keys, credentials, tokens, vulnerable patterns, sinks, sources, endpoints). Each entry shows severity, file path, line number, the matched value, and the surrounding context line.

---

## Severity Levels

| Level  | Categories                       | Meaning |
|--------|----------------------------------|---------|
| HIGH   | `API_KEY`, `CREDENTIAL`, `TOKEN` | Directly exploitable secrets or credentials. |
| MEDIUM | `VULNERABLE`, `SINK`             | Dangerous patterns that may lead to XSS, RCE, or logic flaws. |
| LOW    | `SOURCE`, `ENDPOINT`             | Informational: exposed endpoints, tainted input sources. |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Scan completed. |
| 1    | Invalid usage, file read error, or fatal error. |

---

## Notes on False Positives

The tool uses regex-based heuristics. It is intentionally aggressive to minimize misses, which means it may flag:

- Placeholder keys, test keys, or example keys in documentation.
- Public keys (e.g. Firebase client keys, Stripe publishable keys) — these are not always secrets.
- Minified or obfuscated code where variable names collide with patterns.

Always verify each finding before treating it as a real vulnerability. Findings are deduplicated per (category, match, file), so the same string appearing many times in one file is reported once.

---

## Limitations

- Regex-based detection cannot follow data flow. A match in `SINK` or `SOURCE` is not proof of an exploitable vulnerability; it is a starting point for manual review.
- The crawler does not execute JavaScript. Dynamically injected scripts at runtime will not be discovered.
- Only HTML `<script src>` tags and string literals matching `.js` are extracted during crawling.
- Authentication-protected JS files are not fetched.

---

## Legal

Use this tool only on systems you own or have explicit written permission to test. Unauthorized scanning of third-party assets may violate laws in your jurisdiction. The author assumes no liability for misuse.

---
