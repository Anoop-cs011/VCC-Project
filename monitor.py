import time
import json
import socket
from collections import deque, defaultdict
from scapy.all import sniff, IP, TCP, UDP
import threading

AGENT_VM_IP = "10.128.0.4" # CHANGE THIS TO YOUR AGENT AI IP
log_file = "monitor_log.jsonl"
SESSION_FILE = "session_log.csv"
alert_file = "intrusion_alerts.jsonl"
INTRUSION_ALERTS = deque(maxlen=20)
lock = threading.Lock()

TIME_WINDOW = 2
BATCH_SIZE = 20

recent_connections = defaultdict(deque)
recent_services = defaultdict(deque)
recent_services_per_src = defaultdict(lambda: deque(maxlen=100))
dst_host_conn = defaultdict(deque)
dst_host_srv_conn = defaultdict(deque)

feature_batch = []

def read_login_status(ip):
    try:
        with open(SESSION_FILE, "r") as f:
            lines = f.readlines()
            num_failed_logins = int(lines[0].strip())
            logged_in_ips = [line.split(",")[0] for line in lines[1:] if "," in line]
            return num_failed_logins, int(ip in logged_in_ips)
    except:
        return 0, 0

def ask_agent_batch_prediction(batch_features):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((AGENT_VM_IP, 5000))  # Replace AGENT_VM_IP with actual IP
            message = json.dumps(batch_features).encode()
            sock.sendall(message)
            sock.shutdown(socket.SHUT_WR)  # Let the agent know no more data is coming
            response = sock.recv(4096).decode()
            return json.loads(response)
    except Exception as e:
        print(f"[Monitor] Agent connection failed: {e}")
        return {"prediction": "normal"}


def process_packet(packet):
    global feature_batch

    if IP not in packet:
        return

    ip_layer = packet[IP]
    now = time.time()
    src_ip, dst_ip = ip_layer.src, ip_layer.dst
    proto = ip_layer.proto

    service = "other"
    flag = "OTH"

    if TCP in packet:
        tcp_layer = packet[TCP]
        flag = "S0" if tcp_layer.flags == 0x02 else "SF" if tcp_layer.flags == 0x12 else "REJ" if tcp_layer.flags == 0x04 else "OTH"
        service = {80: "http", 21: "ftp", 22: "ssh", 23: "telnet", 53: "dns"}.get(tcp_layer.dport, "other")
    elif UDP in packet:
        udp_layer = packet[UDP]
        service = {53: "dns"}.get(udp_layer.dport, "other")

    recent_connections[src_ip].append(now)
    recent_services[dst_ip].append(now)
    recent_services_per_src[src_ip].append((now, service))
    dst_host_conn[dst_ip].append(now)
    dst_host_srv_conn[(dst_ip, service)].append(now)

    for dq in [recent_connections[src_ip], recent_services[dst_ip], dst_host_conn[dst_ip], dst_host_srv_conn[(dst_ip, service)]]:
        while dq and now - dq[0] > TIME_WINDOW:
            dq.popleft()

    recent_srvs = recent_services_per_src[src_ip]
    same_srv = sum(1 for _, s in recent_srvs if s == service)
    total_srv = len(recent_srvs)
    same_srv_rate = same_srv / total_srv if total_srv else 0
    diff_srv_rate = 1 - same_srv_rate

    byte_len = len(packet)
    src_bytes, dst_bytes = byte_len // 2, byte_len // 2

    if TCP in packet:
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
        if dst_port in (8080, 80):
            src_bytes, dst_bytes = byte_len, 0
        elif src_port in (8080, 80):
            src_bytes, dst_bytes = 0, byte_len
    
    num_failed_logins, logged_in = read_login_status(src_ip)

    features = {
        "protocol_type": "icmp" if proto == 1 else "tcp" if proto == 6 else "udp",
        "flag": flag,
        "duration": 10,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "land": int(src_ip == dst_ip),
        "wrong_fragment": int(ip_layer.frag > 0),
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": num_failed_logins,
        "logged_in": logged_in,
        "count": len(recent_connections[src_ip]),
        "srv_count": len(recent_services[dst_ip]),
        "same_srv_rate": same_srv_rate,
        "diff_srv_rate": diff_srv_rate,
        "dst_host_count": len(dst_host_conn[dst_ip]),
        "dst_host_srv_count": len(dst_host_srv_conn[(dst_ip, service)]),
        "serror_rate": 0,
        "rerror_rate": 0
    }

    with open(log_file, "a") as f:
        f.write(json.dumps(features) + "\n")

    feature_batch.append((time.time(), src_ip, features))

    if len(feature_batch) >= BATCH_SIZE:
        timestamps, ips, features_only = zip(*feature_batch)
        result = ask_agent_batch_prediction(list(features_only))
        prediction = result.get("prediction", "normal")
        if prediction:
            with lock:
                for ts, ip in zip(timestamps, ips):
                    alert = {"timestamp": ts, "src_ip": ip, "attack_type": prediction}
                    INTRUSION_ALERTS.append(alert)
                    with open(alert_file, "a") as af:
                        af.write(json.dumps(alert) + "\n")
        feature_batch = []

def start_monitor():
    print("[Monitor] Starting packet sniffer...")
    sniff(prn=process_packet, filter="ip", store=0)

monitor_thread = threading.Thread(target=start_monitor)
monitor_thread.start()

def get_alerts():
    with lock:
        return list(INTRUSION_ALERTS)[-10:]
