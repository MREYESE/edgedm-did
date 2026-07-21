# Contributing

Create a focused branch from current `main`, link an Issue, and submit a pull request. Do not push implementation changes directly to `main` or force-push shared branches.

Before requesting review, run:

```bash
make validate
make test
make check-key  # only for an authorized operator with the external test key
git diff --check
```

Never add a private key, private JWK parameter, key backup, token, `.env` file, or private operational endpoint. Do not paste secrets into Issues, pull requests, commit messages, Actions inputs, or logs. CI has no private key and deployment requires none.

Review must confirm exact DID mapping, public-key and fingerprint consistency, relationship references, test-only language, absence of secret material, Pages artifact scope, and passing checks. Key rotation additionally requires coordination with relying test systems.
