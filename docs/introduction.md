# Introduction

## What is repodoctor?

`repodoctor` is a command-line tool that helps open-source maintainers keep
their repositories healthy. It scans your repository for common issues and
produces a prioritized, actionable report.

## Why does it exist?

Maintaining an open-source project involves many responsibilities:

- Keeping governance files up to date (LICENSE, README, CONTRIBUTING, etc.)
- Ensuring no secrets are accidentally committed
- Monitoring dependencies for known vulnerabilities
- Ensuring CI/CD pipelines are configured and running tests
- Maintaining Git repository hygiene (commits, tags, remotes)

It's easy for small issues to slip through. `repodoctor` gives you a single
command to check all of these at once.

## What it does NOT do

- `repodoctor` does not fix issues for you — it reports them with suggestions.
- `repodoctor` does not modify your repository in any way.
- `repodoctor` does not upload your code or secrets anywhere.

## Getting Started

Install repodoctor:

```bash
pip install repodoctor
```

Scan your repository:

```bash
repodoctor scan .
```

Review the output and address the findings in order of severity.
