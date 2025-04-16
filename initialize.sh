#! bin/bash
sudo apt update && sudo apt -y install git python3-pip virtualenv
git clone https://github.com/Anoop-cs011/VCC-assignment3.git
cd VCC-assignment3
virtualenv myProjectEnv
source myProjectEnv/bin/activate
pip install -r requirements.txt
