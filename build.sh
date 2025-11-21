#!/usr/bin/env bash
# Exit on error
set -o errexit

echo "==================================================="
echo "Railway Build Phase - UPI Payment System"
echo "==================================================="

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Create upload directories if they don't exist
echo "Creating upload directories..."
mkdir -p static/uploads/products

echo "==================================================="
echo "Build completed successfully!"
echo "Database will be initialized when app starts..."
echo "==================================================="
