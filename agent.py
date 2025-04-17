import socket
import json
import torch
import torch.nn as nn
import pandas as pd
import numpy as np
from collections import Counter
import os
import subprocess
import logging

# --- Config ---
# Mount bucket path where monitor_log.jsonl is stored
BUCKET_NAME = "monitor-logging"
MOUNT_POINT = "/mnt/gcs_bucket"
LOG_FILE = os.path.join(MOUNT_POINT, "monitor_log.jsonl")
MODEL_FILE = "best_kdd_model.pt"
ATTACK_LIST_FILE = "attack_types.json"

agent_IP = "localhost"
agent_port = 8080 # change this if agent is on a separate VM

logging.basicConfig(filename="monitor_events.log", level=logging.INFO)

feature_order = [
    'duration', 'protocol_type', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_file_creations', 'num_shells', 'num_access_files',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate'
]

categorical_map = {
    "protocol_type": {"icmp": 0, "tcp": 1, "udp": 2},
    "flag": {
        'SF': 0, 'S0': 1, 'REJ': 2, 'RSTR': 3, 'RSTO': 4, 'SH': 5,
        'S1': 6, 'S2': 7, 'RSTOS0': 8, 'S3': 9, 'OTH': 10
    }
}

# Ensure bucket is mounted
def mount_bucket():
    if not os.path.isdir(MOUNT_POINT):
        os.makedirs(MOUNT_POINT)
    result = subprocess.run(["gcsfuse", BUCKET_NAME, MOUNT_POINT], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        logging.error(f"[Monitor] Failed to mount bucket: {result.stderr.decode()}")
    else:
        logging.info(f"[Monitor] Mounted bucket {BUCKET_NAME} at {MOUNT_POINT}")

# --- Model and attack label setup ---
class ANN(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_classes=23):
        super(ANN, self).__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, num_classes)
        )

    def forward(self, x):
        return self.net(x)

def load_attack_labels(path):
    with open(path, "r") as f:
        return json.load(f)

attack_labels = load_attack_labels(ATTACK_LIST_FILE)

def load_model(model_path, input_dim, num_classes):
    model = ANN(input_dim=input_dim, num_classes=num_classes)
    model.load_state_dict(torch.load(model_path, map_location=torch.device('cpu')))
    model.eval()
    return model

model = load_model(MODEL_FILE, input_dim=len(feature_order), num_classes=len(attack_labels))
print("Model loaded...")
# --- Preprocessing ---
def preprocess(entry):
    row = {}
    for key in feature_order:
        val = entry.get(key)
        if key in categorical_map:
            val = categorical_map[key].get(val, 0)
        try:
            val = float(val)
        except:
            val = 0.0
        row[key] = val
    return pd.DataFrame([row])

def get_last_n_logs(n=5):
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()[-n:]
            return [json.loads(line.strip()) for line in lines if line.strip()]
    except Exception as e:
        print(f"[Agent] Log read error: {e}")
        return []

# --- Connection handling ---
def predict_single(entry):
    df = preprocess(entry)
    x = torch.tensor(df.values, dtype=torch.float32)
    with torch.no_grad():
        logits = model(x)
        pred_idx = torch.argmax(torch.softmax(logits, dim=1), dim=1).item()
        return attack_labels[pred_idx]

def predict_batch(entries):
    dfs = [preprocess(e) for e in entries]
    df = pd.concat(dfs, ignore_index=True)
    x = torch.tensor(df.values, dtype=torch.float32)
    with torch.no_grad():
        logits = model(x)
        preds = torch.argmax(torch.softmax(logits, dim=1), dim=1).numpy()
        majority_idx = Counter(preds).most_common(1)[0][0]
        return attack_labels[majority_idx]

def handle_connection(conn):
    with conn:
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            try:
                message = data.decode()
                break
            except UnicodeDecodeError:
                continue

        try:
            if message == "BATCH_REQUEST":
                logs = get_last_n_logs()
                if not logs:
                    response = json.dumps({"prediction": "normal"})
                else:
                    pred = predict_batch(logs)
                    response = json.dumps({"prediction": pred})
            else:
                request = json.loads(message)
                pred = predict_single(request)
                response = json.dumps({"prediction": pred})
        except Exception as e:
            response = json.dumps({"error": str(e)})

        conn.sendall(response.encode())

# --- Agent Server ---
def run_agent(host=agent_IP, port=agent_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"[Agent] Listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            print(f"[Agent] Connection from {addr}")
            handle_connection(conn)

if __name__ == "__main__":
    mount_bucket()
    run_agent()
