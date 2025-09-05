#!/bin/bash
python3 -m venv honeypot
source honeypot/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo "✅ Setup complete."
echo "👉 Run the honeypot with:"
echo "   source honeypot/bin/activate && python honeypot/main.py"