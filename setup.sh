#!/bin/bash
echo "🕷️  ABSpider Setup — Initializing environment..."

# Step 1: Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found! Please install Python 3.8 or above."
    exit 1
fi

# Step 2: Create virtual environment
if [ ! -d ".venv" ]; then
    echo "⚙️  Creating virtual environment..."
    python3 -m venv .venv
fi

# Step 3: Activate venv
echo "🔌 Activating virtual environment..."
source .venv/bin/activate

# Step 4: Install dependencies
echo "📦 Installing dependencies..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "flask
requests
reportlab
beautifulsoup4" > requirements.txt
    pip install -r requirements.txt
fi

# Step 5: Create necessary folders
echo "📁 Setting up directories..."
mkdir -p static/reports static/images

# Step 6: Ensure default proxy list exists
if [ ! -f "proxies.json" ]; then
    echo "[]" > proxies.json
    echo "✅ Created empty proxies.json file."
fi

# Step 7: Optional favicon and logo check
if [ ! -f "static/images/spider.ico" ]; then
    echo "⚠️  No favicon found (static/images/spider.ico). Add your spider icon later."
fi

# Step 8: Launch the app
echo "🚀 Starting ABSpider on http://127.0.0.1:5000/"
python app.py
