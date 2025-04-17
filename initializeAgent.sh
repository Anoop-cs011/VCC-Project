#! bin/bash
sudo apt update && sudo apt -y install git python3-pip virtualenv
git clone https://github.com/Anoop-cs011/VCC-Project.git
cd VCC-Project
virtualenv myProjectEnv
source myProjectEnv/bin/activate
pip install -r requirements.txt
python agent.py
