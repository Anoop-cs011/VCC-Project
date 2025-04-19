import socket
import json
import torch
import torch.nn as nn
import pandas as pd
from collections import Counter

feature_order = [
    'duration', 'protocol_type', 'flag', 'src_bytes', 'dst_bytes', 'land', 
    'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 
    'num_compromised', 'root_shell', 'su_attempted', 'num_file_creations', 
    'num_shells', 'num_access_files', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 
    'serror_rate', 'rerror_rate', 'same_srv_rate', 'diff_srv_rate', 
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 
    'dst_host_srv_diff_host_rate'
]

categorical_map = {
    "protocol_type": {"icmp": 0, "tcp": 1, "udp": 2},
    "flag": {
        'SF': 0, 'S0': 1, 'REJ': 2, 'RSTR': 3, 'RSTO': 4, 'SH': 5,
        'S1': 6, 'S2': 7, 'RSTOS0': 8, 'S3': 9, 'OTH': 10
    }
}

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

attack_labels = json.load(open("attack_types.json"))
model = ANN(len(feature_order), num_classes=len(attack_labels))
model.load_state_dict(torch.load("best_kdd_100_model.pt", map_location=torch.device("cpu")))
model.eval()
print("Model loaded...")

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

def predict_batch(entries):
    df = pd.concat([preprocess(e) for e in entries], ignore_index=True)
    x = torch.tensor(df.values, dtype=torch.float32)
    with torch.no_grad():
        logits = model(x)
        preds = torch.argmax(torch.softmax(logits, dim=1), dim=1).tolist()
        majority = Counter(preds).most_common(1)[0][0]
        return attack_labels[majority]

def handle_connection(conn):
    with conn:
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        try:
            features_batch = json.loads(data.decode())
            prediction = predict_batch(features_batch)
            response = json.dumps({"prediction": prediction})
        except Exception as e:
            response = json.dumps({"error": str(e)})
        conn.sendall(response.encode())

def run_agent(host='0.0.0.0', port=5000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"[Agent] Listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            print(f"[Agent] Connection from {addr}")
            handle_connection(conn)

if __name__ == "__main__":
    run_agent()
