#!/bin/sh
set -eu

EXPECTED=$(
  go run github.com/mikefarah/yq/v4@v4.34.1 \
    '.jobs.lint.steps[] | select(.uses|test("^golangci/golangci-lint-action")) | .with.version' \
    .github/workflows/lint.yaml
)

INSTALLED=$(
  ./bin/golangci-lint --version | awk '{print $4}'
)

INSTALLED="v${INSTALLED}"

echo "expected:  $EXPECTED, installed $INSTALLED"

if [ "$EXPECTED" != "$INSTALLED" ]; then
  echo "Version mismatch, updating..."
  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s ${EXPECTED}
  exit 0
fi

echo "OK: golangci-lint up-to-date"
