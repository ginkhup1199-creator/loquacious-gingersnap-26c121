#!/bin/sh
set -eu

rm -rf .test-dist
npx tsc -p tsconfig.tests.json
node --test .test-dist/tests/validation.test.js
rm -rf .test-dist