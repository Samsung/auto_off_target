#!/bin/bash

# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland
 
echo -e "1. Running python venv module\n"
python3 -m venv venv            || echo "Failed to load the venv module"

echo -e "2. Running activate\n"
source venv/bin/activate        || echo "Failed to activate venv"

echo -e "3. Installing requirements\n"
pip install -r requirements.txt || echo "Failed to install requirements"

echo -e "\n4. All good! You can now run. To exit -> enter 'deactivate'\n" 
