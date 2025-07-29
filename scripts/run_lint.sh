#!/bin/bash
set -e

echo "----------------"
echo "Running ruff..."
ruff check . --fix

echo "----------------"
echo "Running black..."
black .

echo "----------------"
echo "Running flake8..."
flake8 .

echo "----------------"
echo "All linters and formatters finished successfully!"