#! bin/bash
sudo apt update && sudo apt -y install git python3-pip virtualenv curl unzip

echo "deb http://packages.cloud.google.com/apt gcsfuse-focal main" | sudo tee /etc/apt/sources.list.d/gcsfuse.list
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
sudo apt update && sudo apt install -y gcsfuse
mkdir -p /mnt/gcs_bucket
git clone https://github.com/Anoop-cs011/VCC-Project.git
cd VCC-Project
virtualenv myProjectEnv
source myProjectEnv/bin/activate
pip install -r requirements.txt
gunicorn --bind 0.0.0.0:8080 app:app --daemon
sudo ./myProjectEnv/bin/python monitor.py
