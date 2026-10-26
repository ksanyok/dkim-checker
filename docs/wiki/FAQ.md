# FAQ

## How do I find my DKIM selector?

Open any message you sent, view the original/raw source and find the `DKIM-Signature:` header. The `s=` tag is the selector and `d=` is the signing domain. Or run the tool without a selector and let it probe the common ones.

## Is a 1024-bit key still OK?

It still verifies, but 2048 bits has been the recommendation for years and some providers already warn about 1024. Rotate to 2048 when your provider allows it — most do in the admin panel.

## My provider gave me a CNAME, not a TXT record. Is that fine?

Yes. Microsoft 365, SendGrid, Mailchimp and others publish the key on their side and ask you to CNAME the selector to it, so they can rotate keys. The checker follows the CNAME.

## What does a revoked key mean?

A record with an empty `p=` tells receivers that this selector is retired. Any message still signed with it fails DKIM. That is expected for old selectors, and an error only if you still send with it.

## Why does the online tool find a key that the CLI does not?

Usually the selector: the online tool may try a slightly different list. Pass the selector explicitly from the `DKIM-Signature` header and the results will match.
