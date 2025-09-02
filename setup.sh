#!/bin/bash

# Navigate into project directory
cd reconall_v_0.1 || { echo "Directory reconall_v_0.1 not found!"; exit 1; }

# Make Python script executable
sudo chmod +x reconall.py

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install requests rich dnspython shodan

echo "Setup complete. To activate your environment again, run:"
echo "source venv/bin/activate"

