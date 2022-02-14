#!/bin/bash

SINCE=$1
RELEASE=$2
BRANCH="${3:-$(git branch --show-current)}"
OUTFILE="${4:-changelog.out}"

docker run --rm=true -it -v "$(pwd)":/usr/local/src/your-app -v "pomerium-changelog-cache:/cache" ferrarimarco/github-changelog-generator \
    --user pomerium --project pomerium \
    -o "${OUTFILE}" \
    --no-issues \
    --max-issues 500 \
    --usernames-as-github-logins \
    --release-branch "${BRANCH}" \
    --future-release "${RELEASE}" \
    --since-tag "${SINCE}" \
    --token "${GITHUB_TOKEN}" \
    --breaking-label "## Breaking" \
    --enhancement-label "## New" \
    --bugs-label "## Fixed" \
    --pr-label "## Changed" \
    --deprecated-label "## Deprecated" \
    --removed-label "## Removed" \
    --security-label "## Security" \
    --cache-file /cache \
    --enhancement-labels "improvement,Improvement,enhancement,Enhancement,feature" \
    --exclude-labels "docs,ci" \
    --add-sections '{"documentation":{"prefix":"## Documentation","labels":["docs"]}, "dependency":{"prefix":"## Dependency","labels":["dependency","dependencies"]}, "deployment":{"prefix":"## Deployment","labels":["deployment"]}}'
