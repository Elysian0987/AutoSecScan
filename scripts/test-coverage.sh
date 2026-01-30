#!/bin/bash

# Test Coverage Script for AutoSecScan
# Run all tests with coverage reporting

set -e

echo "🧪 Running AutoSecScan Test Suite with Coverage"
echo "=============================================="

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Create coverage directory
mkdir -p coverage

echo ""
echo "📊 Running tests with coverage..."

# Run tests with coverage
go test -v -race -coverprofile=coverage/coverage.out -covermode=atomic ./...

# Check if tests passed
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✅ All tests passed!${NC}"
else
    echo ""
    echo -e "${RED}❌ Some tests failed${NC}"
    exit 1
fi

# Generate coverage report
echo ""
echo "📈 Generating coverage report..."
go tool cover -html=coverage/coverage.out -o coverage/coverage.html

# Display coverage summary
echo ""
echo "📋 Coverage Summary:"
go tool cover -func=coverage/coverage.out | tail -n 1

# Calculate coverage percentage
COVERAGE=$(go tool cover -func=coverage/coverage.out | tail -n 1 | awk '{print $3}' | sed 's/%//')

echo ""
echo "📊 Total Coverage: ${COVERAGE}%"

# Check if coverage meets threshold
THRESHOLD=60
if (( $(echo "$COVERAGE >= $THRESHOLD" | bc -l) )); then
    echo -e "${GREEN}✅ Coverage meets threshold (${THRESHOLD}%)${NC}"
else
    echo -e "${YELLOW}⚠️  Coverage below threshold (${THRESHOLD}%)${NC}"
fi

echo ""
echo "📄 Detailed HTML report: coverage/coverage.html"
echo "💡 Open the HTML file in your browser to see detailed coverage"

# Optional: Open coverage report in browser (uncomment if desired)
# xdg-open coverage/coverage.html 2>/dev/null || open coverage/coverage.html 2>/dev/null || echo "Please open coverage/coverage.html manually"
