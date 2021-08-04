# Overall process

1. Add new branch to netlify build settings (new release branch only)
2. Request new subdomain for netlify TLS certificate (new release branch only)
3. Generate changelog
4. Update docs/upgrading.md for major/minor releases
5. Update vuepress branch config in `config.js`
   1. Set new default text nav
   2. Add new branch to item list
6. Create a new release branch for major/minor releases, eg `0-15-0`, off master.  Patch releases use existing release branches.
7. Create Github release with name and tag matching `v[version]` on the appropriate release branch.
8. Copy/paste changelog from generated output into Github release notes
9.  GH automation should take it from there and build/upload artifacts
10. Update default branch on netlify to new release branch (new release branch only)

# Changelog generation

`./scripts/changelog.sh [previous version] [next version] [branch]`

This script requires docker running and GITHUB_TOKEN set with a PAT.

The changelog will be written to changelog.out

## Major/minor release example

```bash
GITHUB_TOKEN=XXXXXX ./changelog.sh v0.14.0 v0.15.0 master changelog.out
```

## Patch release example

```bash
GITHUB_TOKEN=XXXXXX ./changelog.sh v0.14.6 v0.14.7 master changelog.out
```

# Release branches

For each major or minor release, we create a release branch `[major]-[minor]-0`.  This is to allow feature freeze ahead of actual release and provide a stable branch to apply patches onto for bug fixes.

These branches are to be protected and may receive updates via backport or direct PR.
