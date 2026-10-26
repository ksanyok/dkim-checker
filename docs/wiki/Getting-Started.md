# Getting started

## Requirements

Node.js 18 or newer. No other dependencies.

## Install

```bash
# one-off run
npx github:ksanyok/dkim-checker example.com google

# global CLI
npm install -g github:ksanyok/dkim-checker

# as a library in your project
npm install github:ksanyok/dkim-checker
```

## First run

```bash
dkim-checker example.com google
```

Each selector is listed with its status: the key type and length, `revoked`, `not found` or a DNS error. When probing, only selectors that exist are shown. Below that, problems are grouped by selector: `✖` errors break signing, `!` warnings weaken it. Exit code is 1 when no key was found or any key has errors.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No errors (warnings allowed unless `--strict`) |
| 1 | Errors found (or warnings with `--strict`) |
| 2 | Bad arguments or the check could not run |

## More examples

**Probe common selectors when you do not know yours**

```bash
dkim-checker example.com
```

**Check specific selectors**

```bash
dkim-checker example.com selector1 selector2
dkim-checker example.com -s google,k1
```

**Lint a key record before publishing it**

```bash
dkim-checker --record "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
```

**JSON for monitoring scripts**

```bash
dkim-checker example.com google --json | jq '.selectors[] | {selector, bits: .key.bits}'
```

## Without installing anything

Use the [online DKIM Checker](https://promopilot.link/en/tools/dkim-checker.php?utm_source=github&utm_medium=repo&utm_campaign=tools&utm_content=dkim-checker).
