# Troubleshooting

## "No DKIM key found for common selectors"

Your provider uses a selector that is not in the built-in list. Find it in the `DKIM-Signature` header (`s=` tag) of a sent message and pass it: `dkim-checker example.com <selector>`.

## "Public key cannot be decoded"

The `p=` value was damaged when pasted into the DNS panel — usually a missing chunk, an extra quote or a space. Copy the record again from your mail provider. Long keys must be split into 255-character strings, which this tool joins automatically.

## A key works for me but receivers say "no key for signature"

Check that the record is at `selector._domainkey.example.com`, not `selector._domainkey.example.com.example.com` — many DNS panels append the domain to the host name.

## DNS errors (ETIMEOUT, ESERVFAIL)

Your resolver did not answer. Retry, lower `concurrency`, or pass your own `resolveTxt` when using the library.

## Still stuck?

Open an [issue](https://github.com/ksanyok/dkim-checker/issues/new/choose) with the command, the output (`--json` if possible) and your Node.js version — or compare with the [online version](https://promopilot.link/en/tools/dkim-checker.php?utm_source=github&utm_medium=repo&utm_campaign=tools&utm_content=dkim-checker).
