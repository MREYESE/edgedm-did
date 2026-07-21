# Security policy

## Supported status

This repository supports only a public, test-only identity. It is not production-ready, governance-approved, connector-onboarded, or legally verified. No production security assurance or regulated key custody is offered.

## Reporting accidental exposure

If private-key material, a token, or another secret may have been exposed, do not open a public Issue containing it. Revoke or rotate the affected secret immediately, preserve only non-secret evidence, and contact the repository owner through a private trusted channel available in the owner’s GitHub profile or organization process.

An exposed test private key must be treated as compromised and rotated immediately. Review repository history, Actions logs, artifacts, caches, forks, and affected test assertions. Removing a current file does not erase prior disclosure; coordinate remediation with relying test systems.

Never attach private keys, private JWK members, credentials, backups, or secret-bearing logs to an Issue or pull request.
