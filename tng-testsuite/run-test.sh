#!/bin/bash

# Helper script to run unit and integration tests.

set -euo pipefail

project_root=$(dirname "$(realpath "$0")")/../
cd "$project_root"

export RUST_BACKTRACE=1

failed=0
test_result_msgs=""

# Run unit tests
echo "============= Starting unit test ============="
test_result_msgs="${test_result_msgs}\n============= Unit tests ============="

if cargo test --workspace --bins --lib --exclude tng-wasm -- --nocapture; then
    test_result_msgs="${test_result_msgs}\nunit test:\tPASS"
else
    test_result_msgs="${test_result_msgs}\nunit test:\tFAILED"
    failed=1
fi

# Run integration tests
test_cases=$(ls tng-testsuite/tests/ | grep -E '.*\.rs$' | sed 's/\.rs$//')

test_result_msgs="${test_result_msgs}\n============= Integration tests ============="

for case_name in $test_cases; do
    echo "============= Starting integration test case: $case_name ============="

    if cargo test --no-default-features --features on-source-code --package tng-testsuite \
        --test "$case_name" -- --nocapture; then
        test_result_msgs="${test_result_msgs}\n${case_name}:\tPASS"
    else
        test_result_msgs="${test_result_msgs}\n${case_name}:\tFAILED"
        failed=1
    fi
done

test_result_msgs="${test_result_msgs}\n============= All tests finished ============="

echo -e "$test_result_msgs"

exit $failed
