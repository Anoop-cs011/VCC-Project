from flask import Flask, request, redirect, render_template
# import monitor  # only for get_alerts()
import os
import socket
import json

app = Flask(__name__)
USER_FILE = "users.txt" # to store user login info
SESSION_FILE = "session_log.csv" # to store current logged in users info
alert_file = "intrusion_alerts.jsonl" # to read intrusion alerts

open(USER_FILE, "a").close()
if not os.path.exists(SESSION_FILE):
    with open(SESSION_FILE, "w") as f:
        f.write("0\n")  # failed login counter

# Utility functions
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # doesn't even have to be reachable
        s.connect(('10.254.254.254', 1)) # random unreachable IP
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def load_users():
    with open(USER_FILE) as f:
        return dict(line.strip().split(",") for line in f if "," in line)

def save_user(username, password):
    with open(USER_FILE, "a") as f:
        f.write(f"{username},{password}\n")

def update_failed_logins(increment=True):
    with open(SESSION_FILE, "r+") as f:
        lines = f.readlines()
        count = int(lines[0].strip()) if lines else 0
        if increment:
            count += 1
        lines[0] = f"{count}\n"
        f.seek(0)
        f.writelines(lines)
        f.truncate()

def add_logged_in_user(ip, username):
    with open(SESSION_FILE, "a") as f:
        f.write(f"{ip},{username}\n")

def remove_logged_in_user(ip, username):
    with open(SESSION_FILE, "r") as f:
        lines = f.readlines()
    with open(SESSION_FILE, "w") as f:
        f.write(lines[0])  # keep the counter
        for line in lines[1:]:
            if line.strip() != f"{ip},{username}":
                f.write(line)

def is_user_logged_in(ip):
    with open(SESSION_FILE) as f:
        lines = f.readlines()[1:]  # skip counter
    for line in lines:
        if line.startswith(ip + ","):
            return True
    return False

def get_alerts():
    try:
        with open(alert_file, "r") as f:
            alerts = [json.loads(line.strip()) for line in f if line.strip()][-5:]
        for i in range(len(alerts)):
            alerts[i] = tuple(alerts[i].values())
        return alerts
    except FileNotFoundError:
        print("[App] File not found")
        return []

# Routes
@app.route("/")
def index():
    return redirect("/login")

# Login page
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        ip = request.remote_addr
        users = load_users()
        if username in users and users[username] == password:
            add_logged_in_user(ip, username)
            return redirect(f"/home/{username}")
        else:
            update_failed_logins()
            error = "Invalid credentials"
    return render_template("login.html", error=error)

# Registration page
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        users = load_users()
        if username in users:
            error = "Username already exists"
        else:
            save_user(username, password)
            return redirect("/login")
    return render_template("register.html", error=error)

# user home page
@app.route("/home/<username>")
def home(username):
    return render_template("home.html", username=username)

# serach names of other users
@app.route("/search", methods=["GET", "POST"])
def search():
    results = []
    username = request.args.get("username", "guest")
    if request.method == "POST":
        query = request.form["query"]
        results = [u for u in load_users() if query.lower() in u.lower()]
    return render_template("search.html", results=results, username=username)

# Check alerts
@app.route("/alerts")
def alerts():
    username = request.args.get("username", "guest")
    alerts = get_alerts()
    return render_template("alerts.html", alerts=alerts, username=username)

# logout
@app.route("/logout/<username>")
def logout(username):
    ip = request.remote_addr
    remove_logged_in_user(ip, username)
    return redirect("/login")

if __name__ == "__main__":
    app.run(host= "0.0.0.0", port=8080, debug=True)
