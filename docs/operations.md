# Operations

## Validation and deployment

Run `make validate` and `make test` for any public change. Operators who possess the external test key also run `make check-key`; CI intentionally cannot. Pull requests execute `.github/workflows/ci.yml` with read-only repository permission and do not deploy.

After merge to `main`, `.github/workflows/deploy-pages.yml` repeats local validation and tests, scans for private-key material, configures Pages, uploads only `site/`, and deploys to the `github-pages` environment. The workflow may also be started manually with **Actions → Deploy GitHub Pages → Run workflow**. Repository Pages settings must use **GitHub Actions** as the build source and must not configure a custom domain for this identity.

## Post-deployment checks

1. Confirm the Pages workflow succeeded for the merged commit.
2. Fetch `https://mreyese.github.io/edgedm-did/` and `https://mreyese.github.io/edgedm-did/did.json` over HTTPS.
3. Run `python3 scripts/validate_identity.py --remote`.
4. Compare the deployed DID bytes with `site/did.json` and inspect status, content type, cache, redirect, and CORS headers.
5. Exercise the exact DID in the intended test dataspace without inferring universal resolver compatibility.

## Rollback

Revert the faulty merge through a reviewed pull request, run validation, merge the revert, and observe the resulting Pages deployment. Do not force-push `main`. A rollback that changes verification material must be coordinated with relying systems.

## Deactivation

For planned test deactivation, use a reviewed change to remove active verification capabilities or stop publication according to relying-system expectations, then verify resolver behavior. Preserve an incident or decision record without publishing secrets. GitHub Pages does not provide a DID deactivation registry.

## Incident response and troubleshooting

For suspected key exposure, follow `SECURITY.md`, rotate immediately, and assess affected test assertions. For CI failures, reproduce locally and fix the cause rather than weakening checks. For Pages failures, inspect the failed Actions logs, verify Pages uses the workflow source, confirm the artifact contains only `site/`, and check repository/environment permissions. HTTP publication can lag briefly after a successful deployment; use bounded retries before declaring failure.
