# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

We take the security of repodoctor seriously. If you believe you have found a
security vulnerability, please report it to us in a responsible manner.

### Please do

- **Use GitHub's private vulnerability reporting flow** once it is enabled for
  this repository. It is available from the repository's Security tab.
- **Include** steps to reproduce, affected versions, and potential impact.
- **Give** us reasonable time to investigate and respond before disclosing
  publicly.

### Please do not

- **Do not** open a public GitHub issue for security vulnerabilities.
- **Do not** share the vulnerability with third parties before we've had a
  chance to address it.
- **Do not** attempt to access data or systems you are not authorized to access.

If private vulnerability reporting is not yet available, open a minimal public
issue without exploit details or sensitive information and request a private
reporting channel from a maintainer.

## Response Timeline

- We will acknowledge receipt of your report within 5 business days.
- We will provide an initial assessment within 10 business days.
- We will work with you to understand and resolve the issue.
- We will credit you in our security advisories (unless you prefer to remain
  anonymous).

## Disclosure Policy

Once a vulnerability is confirmed and fixed, we will:

1. Release a patched version as soon as possible.
2. Publish a security advisory describing the vulnerability and its fix.
3. Credit the reporter (if they wish to be credited).
4. Notify users through our standard release channels.

## Security Measures in repodoctor

`repodoctor` is designed with security in mind:

- **Read-only scanning**: `repodoctor` never modifies your repository.
- **No data exfiltration**: `repodoctor` never uploads source code, secrets,
  or repository contents to any external service.
- **No secret logging**: Detected secret values are never printed to stdout or
  stored in logs.
- **Local-only processing**: All scanning happens on your machine.
