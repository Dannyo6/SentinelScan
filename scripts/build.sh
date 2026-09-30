#!/usr/bin/env bash
# exit on error
set -o errexit

echo "Installing Python dependencies..."
pip install -r requirements.txt

echo "Installing Node dependencies..."
npm --prefix apps/frontend/react-app install

echo "Building React frontend..."
npm --prefix apps/frontend/react-app run build

echo "Build complete!"
