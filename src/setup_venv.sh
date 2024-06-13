#!/bin/bash

# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland
 
echo -e "1. Creating virtual environment.\n"
python3 -m venv venv            || echo "Failed to load the venv module."

echo -e "2. Activating virtual environment.\n"
source venv/bin/activate        || echo "Failed to activate venv."

echo -e "3. Installing requirements.\n"
pip3 install -r requirements.txt || echo "Failed to install requirements."

echo -e "\n4. All good! You are now within the virtual environment. Run the 'deactivate' command to exit.\n" 
