#!/bin/bash
#
# Integration test for Watchtower batch scanner
# This script demonstrates the watchtower functionality with a small test repository
#

set -e  # Exit on error

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"
TEST_CSV="${PROJECT_ROOT}/examples/test_watchtower_integration.csv"
TEST_OUTPUT="/tmp/watchtower_test_output"

echo "================================================"
echo "Watchtower Integration Test"
echo "================================================"
echo ""

# Cleanup from previous runs
echo "Cleaning up previous test data..."
rm -rf "${TEST_OUTPUT}"
rm -f "${PROJECT_ROOT}/watchtower.log"

# Create a minimal test CSV with a very small public repo
cat > "${TEST_CSV}" << 'EOF'
org,repo,status,url
octocat,Hello-World,NEW,https://github.com/octocat/Hello-World
EOF

echo "Created test CSV: ${TEST_CSV}"
echo ""

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v git &> /dev/null; then
    echo "ERROR: git is not installed"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 is not installed"
    exit 1
fi

# Check if Hound is configured
if [ ! -f "${PROJECT_ROOT}/hound.py" ]; then
    echo "ERROR: hound.py not found at ${PROJECT_ROOT}/hound.py"
    exit 1
fi

echo "✓ All prerequisites met"
echo ""

# Display test configuration
echo "Test Configuration:"
echo "  CSV File: ${TEST_CSV}"
echo "  Output Directory: ${TEST_OUTPUT}"
echo "  Project Root: ${PROJECT_ROOT}"
echo ""

# Check for API keys (warn if missing)
if [ -z "${OPENAI_API_KEY}${DEEPSEEK_API_KEY}${ANTHROPIC_API_KEY}" ]; then
    echo "WARNING: No LLM API keys detected in environment"
    echo "  Set one of: OPENAI_API_KEY, DEEPSEEK_API_KEY, or ANTHROPIC_API_KEY"
    echo ""
    echo "This test will verify CSV parsing and repository cloning only."
    echo "Full audit functionality requires API keys."
    echo ""
fi

# Run CSV parsing test only
echo "================================================"
echo "Test 1: CSV Parsing"
echo "================================================"
echo ""

python3 -c "
import sys
sys.path.insert(0, '${PROJECT_ROOT}')
from scripts.watchtower import WatchtowerScanner

scanner = WatchtowerScanner('${TEST_CSV}', output_dir='${TEST_OUTPUT}')
repos = scanner.parse_csv()

print(f'✓ Successfully parsed {len(repos)} repositories:')
for r in repos:
    print(f'  - {r[\"org\"]}/{r[\"repo\"]} ({r[\"status\"]})')
print()
"

if [ $? -eq 0 ]; then
    echo "✓ CSV parsing test PASSED"
else
    echo "✗ CSV parsing test FAILED"
    exit 1
fi

echo ""
echo "================================================"
echo "Test 2: Repository Cloning (Dry Run)"
echo "================================================"
echo ""

# Test git clone separately
TEST_CLONE_DIR="/tmp/watchtower_test_clone"
rm -rf "${TEST_CLONE_DIR}"

echo "Testing git clone to ${TEST_CLONE_DIR}..."
if git clone --depth 1 https://github.com/octocat/Hello-World "${TEST_CLONE_DIR}" > /dev/null 2>&1; then
    echo "✓ Repository clone test PASSED"
    ls -lh "${TEST_CLONE_DIR}"
    rm -rf "${TEST_CLONE_DIR}"
else
    echo "✗ Repository clone test FAILED"
    echo "  Check internet connection or repository accessibility"
    exit 1
fi

echo ""
echo "================================================"
echo "Test 3: Help and CLI Interface"
echo "================================================"
echo ""

if python3 "${PROJECT_ROOT}/scripts/watchtower.py" --help > /dev/null; then
    echo "✓ CLI interface test PASSED"
else
    echo "✗ CLI interface test FAILED"
    exit 1
fi

echo ""
echo "================================================"
echo "Integration Test Summary"
echo "================================================"
echo ""
echo "✓ All basic tests PASSED"
echo ""
echo "To run a full end-to-end test with auditing:"
echo "  1. Configure LLM API keys (see main README)"
echo "  2. Run: python scripts/watchtower.py ${TEST_CSV}"
echo ""
echo "Note: Full audits may take several minutes per repository"
echo "      and will consume API credits."
echo ""
