#!/bin/bash
# Quick setup script for AgentZero109

echo "🎯 Setting up AgentZero109..."
echo ""

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python version: $python_version"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt -q
echo "✓ Dependencies installed"

# Create necessary directories
echo "Creating output directories..."
mkdir -p reports
mkdir -p audit_logs
mkdir -p findings
echo "✓ Directories created"

# Make CLI executable
chmod +x cli/agentzero.py
echo "✓ CLI made executable"

echo ""
echo "✅ Setup complete!"
echo ""
echo "To use AgentZero109:"
echo "  1. Activate the virtual environment: source venv/bin/activate"
echo "  2. Run: python cli/agentzero.py -t https://example.com"
echo ""
echo "Or install system-wide:"
echo "  pip install -e ."
echo "  agentzero -t https://example.com"
echo ""
