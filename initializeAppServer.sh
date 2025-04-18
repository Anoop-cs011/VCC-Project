#! bin/bash
sudo apt update && sudo apt -y install git python3-pip virtualenv unzip apt-transport-https ca-certificates gnupg curl
sudo apt -y install python3-scapy
git clone https://github.com/Anoop-cs011/VCC-Project.git
cd VCC-Project
virtualenv myProjectEnv
source myProjectEnv/bin/activate
pip install -r requirements.txt
gunicorn --bind 0.0.0.0:8080 app:app --daemon
sudo python3 monitor.py
