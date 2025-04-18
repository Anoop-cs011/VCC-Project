#! bin/bash
sudo apt update && sudo apt -y install git python3-pip virtualenv unzip apt-transport-https ca-certificates gnupg curl
echo "deb http://packages.cloud.google.com/apt gcsfuse-focal main" | sudo tee /etc/apt/sources.list.d/gcsfuse.list
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
sudo apt update && sudo apt install -y gcsfuse
mkdir -p ~/gcs_bucket
git clone https://github.com/Anoop-cs011/VCC-Project.git
cd VCC-Project
virtualenv myProjectEnv
source myProjectEnv/bin/activate
pip install -r requirements.txt
python agent.py
