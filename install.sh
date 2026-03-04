#!/usr/bin/env bash
# PortSwigger Cookie Analyzer — Quick install helper
set -e

echo "🔐 PortSwigger Cookie Analyzer — Setup"
echo "======================================="

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "❌ Python 3 not found. Install from https://python.org"
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "✅ Python $PY_VER found"

# Check tkinter
if ! python3 -c "import tkinter" 2>/dev/null; then
    echo "⚠  tkinter not found. Installing..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get install -y python3-tk
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y python3-tkinter
    elif command -v brew &>/dev/null; then
        brew install python-tk
    else
        echo "❌ Cannot auto-install tkinter. Please install python3-tk manually."
        exit 1
    fi
fi
echo "✅ tkinter available"

# Check Java (optional, for ysoserial)
if command -v java &>/dev/null; then
    JAVA_VER=$(java -version 2>&1 | head -1)
    echo "✅ Java found: $JAVA_VER"
else
    echo "⚠  Java not found (optional — needed only for ysoserial tab)"
    echo "   Install with: sudo apt install default-jdk"
fi

echo ""
echo "✅ Setup complete! Run with:"
echo "   python3 tool.py"
echo ""
echo "🌐 Web UI will be available at: http://127.0.0.1:8990"
