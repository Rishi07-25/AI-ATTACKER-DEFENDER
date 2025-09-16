import time
import json
import re
import threading
import requests
import google.generativeai as genai
from flask import Flask, render_template_string, request, Response
import os
import sqlite3
import random

# IMPORTANT: Replace "YOUR_API_KEY_HERE" with your actual, valid API key.
genai.configure(api_key="API Key")

app = Flask(__name__)

# --- Persistent State Files ---
PATCH_FILE = 'patches.json'
HISTORY_FILE = 'battle_history.json'

def load_patches():
    default_patches = {
        "sql_injection_patched": False,
        "xss_patched": False,
        "ddos_patched": False,
        "brute_force_patched": False,
        "pathtraversal_patched": False
    }
    if not os.path.exists(PATCH_FILE):
        with open(PATCH_FILE, 'w') as f:
            json.dump(default_patches, f)
        return default_patches
    with open(PATCH_FILE, 'r') as f:
        patches = json.load(f)
        for key, value in default_patches.items():
            if key not in patches:
                patches[key] = value
        return patches

def apply_patch(vulnerability_type):
    patches = load_patches()
    patches[f"{vulnerability_type}_patched"] = True
    with open(PATCH_FILE, 'w') as f:
        json.dump(patches, f, indent=4)

def load_history():
    if not os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'w') as f:
            json.dump({"last_winner": "none", "attacker_score": 0, "defender_score": 0}, f)
        return {"last_winner": "none", "attacker_score": 0, "defender_score": 0}
    with open(HISTORY_FILE, 'r') as f:
        return json.load(f)

def save_history(winner, attacker_score, defender_score):
    history = {"last_winner": winner, "attacker_score": attacker_score, "defender_score": defender_score}
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=4)

# --- AI and Core Simulation Logic ---
def get_ai_response(prompt_history):
    model = genai.GenerativeModel('gemini-1.5-flash-latest')
    try:
        if isinstance(prompt_history, dict):
            response = model.generate_content(prompt_history)
        else:
            chat = model.start_chat(history=prompt_history)
            response = chat.send_message("What's your next move?")
        
        match = re.search(r'\{.*\}', response.text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
    except Exception as e:
        print(f"Error getting AI response: {e}")
    return None

def get_defender_response(log_entry, strategy_boost=""):
    prompt_parts = ["You are 'Blue AI', a security analyst. Analyze the following log entry and provide an analysis of the attack, the type of vulnerability, and a suggested mitigation. Your response must be a single JSON object with 'analysis', 'vulnerability_type', and 'mitigation' keys. Do not include any text outside the JSON object.",f"Log entry: {log_entry}"]
    if strategy_boost:
        prompt_parts.append(strategy_boost)
    prompt = {"role": "user", "parts": prompt_parts}
    return get_ai_response(prompt)

# --- Vulnerable Server Logic ---
def run_vulnerable_server():
    from flask import Flask, render_template_string, request, jsonify
    server = Flask(__name__)
    patches = load_patches()
    
    # SQL Injection Vulnerability
    @server.route('/login', methods=['POST'])
    def login():
        username = request.form.get('username')
        password = request.form.get('password')
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        if patches["sql_injection_patched"]:
            query = "SELECT * FROM users WHERE username = ? AND password = ?"
            cursor.execute(query, (username, password))
            user = cursor.fetchone()
            conn.close()
            if user: return jsonify({"status": "success", "message": "Welcome, admin!"})
            else: return jsonify({"status": "failed", "message": "Invalid credentials. Input sanitized."})
        else:
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            if user: return jsonify({"status": "success", "message": "Welcome, admin!"})
            else: return jsonify({"status": "failed", "message": "Invalid credentials."})

    # XSS Vulnerability
    @server.route('/search', methods=['GET'])
    def search():
        search_query = request.args.get('q', '')
        if patches["xss_patched"]:
            return render_template_string(f"<div><p>Search results: {json.dumps(search_query)}</p></div>")
        else:
            return render_template_string(f"<div><p>Search results: {search_query}</p></div>")

    # DDoS Vulnerability
    request_count = {}
    @server.route('/overload', methods=['GET'])
    def overload():
        ip = request.remote_addr
        request_count[ip] = request_count.get(ip, 0) + 1
        if not patches["ddos_patched"] and request_count[ip] > 10:
            return "Server Overloaded!", 503
        else:
            return "Still running...", 200

    # Brute Force Vulnerability
    failed_attempts = {}
    @server.route('/bruteforce_login', methods=['POST'])
    def bruteforce_login():
        username = request.form.get('username')
        password = request.form.get('password')
        global failed_attempts
        failed_attempts[username] = failed_attempts.get(username, 0) + 1
        if not patches["brute_force_patched"] and failed_attempts[username] > 5:
            return jsonify({"status": "failed", "message": "Too many failed attempts."}), 429
        if username == 'admin' and password == 'secure_password':
            return jsonify({"status": "success", "message": "Login successful."})
        return jsonify({"status": "failed", "message": "Invalid credentials."})

    # Path Traversal Vulnerability
    @server.route('/file')
    def get_file():
        filename = request.args.get('file', '')
        if not patches["pathtraversal_patched"]:
            base_path = os.path.join(os.getcwd(), 'static')
            filepath = os.path.normpath(os.path.join(base_path, filename))
            if not filepath.startswith(base_path):
                return "Path traversal attempt detected!", 403
            try:
                with open(filepath, 'r') as f:
                    return f.read(), 200
            except FileNotFoundError:
                return "File not found.", 404
        else:
            try:
                safe_filename = os.path.basename(filename)
                with open(os.path.join('static', safe_filename), 'r') as f:
                    return f.read(), 200
            except FileNotFoundError:
                return "File not found.", 404

    server.run(debug=False, port=5001)

def setup_database():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL)''')
    cursor.execute('DELETE FROM users')
    cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'secure_password')")
    conn.commit()
    conn.close()

# --- Main Simulation Orchestration ---
def generate_events(scenario):
    yield f'data: {{"log": "Starting {scenario} simulation...", "type": "status"}}\n\n'
    patches = load_patches()
    is_patched = patches[f"{scenario}_patched"]
    history = load_history()
    
    if is_patched:
        yield f'data: {{"log": "✅ Vulnerability already patched. Attacker will fail.", "type": "status"}}\n\n'
    else:
        yield f'data: {{"log": "🚨 Vulnerability is active. Attacker has a chance to succeed.", "type": "status"}}\n\n'
    
    time.sleep(1)
    
    attacker_score = 0
    defender_score = 0
    
    attacker_prompt_history = []
    
    attacker_boost_prompt = ""
    defender_boost_prompt = ""
    if history['last_winner'] == 'defender':
        attacker_boost_prompt = "You lost the last battle. Analyze your defeat and devise a new strategy to bypass the defender's patches. Try more advanced techniques."
        yield f'data: {{"log": "Red AI has a strategic advantage from its last loss.", "type": "status"}}\n\n'
    elif history['last_winner'] == 'attacker':
        defender_boost_prompt = "You lost the last battle. Analyze the attacker's winning strategy and implement a more robust defense."
        yield f'data: {{"log": "Blue AI has a strategic advantage from its last loss.", "type": "status"}}\n\n'

    for i in range(5):
        yield f'data: {{"log": "\\n--- Round {i+1} ---", "type": "round"}}\n\n'
        yield f'data: {{"log": "Attacker AI is thinking...", "type": "attacker"}}\n\n'
        
        attack_successful = False
        server_response_text = ""
        response_code = 200

        # --- Attacker's turn - AI generates the payload ---
        if scenario == 'sql_injection':
            prompt_parts = [f"You are a SQL injection penetration tester. Your goal is to bypass a login form. You must respond with a JSON object with 'action' (try_login) and 'details' (username, password). {attacker_boost_prompt}"]
            attacker_action = get_ai_response({"role": "user", "parts": prompt_parts})
            if not attacker_action: attacker_action = {"action": "try_login", "details": {"username": "admin", "password": "' OR 'a'='a' --"}}
            
            payload = attacker_action['details']['password']
            try:
                response = requests.post('http://127.0.0.1:5001/login', data={'username': attacker_action['details']['username'], 'password': payload})
                response_code = response.status_code
                server_response_text = response.json().get("message", "")
                if "Welcome" in server_response_text: attack_successful = True
            except requests.exceptions.RequestException as e: server_response_text = str(e)
        
        elif scenario == 'xss':
            prompt_parts = [f"You are a Cross-Site Scripting (XSS) penetration tester. Your goal is to inject a malicious payload into a search form on 'http://127.0.0.1:5001/search'. You must respond with a JSON object with 'action' (submit_search) and 'payload'. {attacker_boost_prompt}"]
            attacker_action = get_ai_response({"role": "user", "parts": prompt_parts})
            if not attacker_action: attacker_action = {"action": "submit_search", "payload": "<script>alert('XSS');</script>"}
            
            payload = attacker_action['payload']
            try:
                response = requests.get('http://127.0.0.1:5001/search', params={'q': payload})
                response_code = response.status_code
                server_response_text = "Malicious script found in output." if payload in response.text else "Payload was not executed."
                if payload in response.text: attack_successful = True
            except requests.exceptions.RequestException as e: server_response_text = str(e)
        
        elif scenario == 'brute_force':
            # This is hard to get AI to do round by round, so we will simulate this part
            passwords = ['123456', 'password', 'qwerty', 'admin123', 'secure_password']
            payload = random.choice(passwords)
            if i == 4: payload = 'secure_password'
            try:
                response = requests.post('http://127.0.0.1:5001/bruteforce_login', data={'username': 'admin', 'password': payload})
                response_code = response.status_code
                server_response_text = response.json().get("message", "")
                if "Login successful" in server_response_text: attack_successful = True
            except requests.exceptions.RequestException as e: server_response_text = str(e)

        elif scenario == 'ddos':
            pass
        elif scenario == 'pathtraversal':
            pass

        yield f'data: {{"log": "Server response: {server_response_text}", "type": "server"}}\n\n'
        
        if attack_successful and not is_patched:
            yield f'data: {{"log": "💥 Attack was successful! The system is compromised.", "type": "compromised"}}\n\n'
            apply_patch(scenario)
            attacker_score += 1
            break
        elif is_patched and attack_successful:
            yield f'data: {{"log": "❌ Attack failed. The system is secure.", "type": "failed"}}\n\n'
            defender_score += 1
        elif not attack_successful:
            yield f'data: {{"log": "❌ Attack failed. The system is secure.", "type": "failed"}}\n\n'
            defender_score += 1
            
        yield f'data: {{"log": "\\nDefender AI is analyzing...", "type": "defender"}}\n\n'
        
        log_entry = f"The previous attempt failed. The server's response was: '{server_response_text}'. The HTTP status was {response_code}."
        defender_response = get_defender_response(log_entry, strategy_boost=defender_boost_prompt)
        
        if defender_response:
            yield f'data: {{"log": "Defender Analysis: {defender_response.get("analysis")}"}}\n\n'
            yield f'data: {{"log": "Vulnerability: {defender_response.get("vulnerability_type")}", "type": "defender"}}\n\n'
            yield f'data: {{"log": "Mitigation: {defender_response.get("mitigation")}", "type": "defender"}}\n\n'

    # --- Final Score and History Save ---
    winner = "attacker" if attacker_score > defender_score else "defender"
    yield f'data: {{"log": "\\n--- FINAL SCORE: Attacker {attacker_score} vs Defender {defender_score} ---", "type": "status"}}\n\n'
    yield f'data: {{"log": "🎉 The winner is the {winner}!", "type": "compromised" if winner == "attacker" else "defender"}}\n\n'
    
    save_history(winner, attacker_score, defender_score)
    
    yield f'data: {{"log": "\\n--- Simulation Complete ---", "type": "status"}}\n\n'
    yield 'data: {"log": "END_OF_SIMULATION"}\n\n'

@app.route('/')
def index_page():
    return render_template_string("""
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>AI Attacker vs Defender</title>
        <style>
            @font-face { font-family: 'VT323'; src: url('https://fonts.googleapis.com/css2?family=VT323&display=swap'); }
            body { font-family: 'VT323', monospace; background-color: #000; color: #0f0; padding: 20px; }
            .container { max-width: 900px; margin: auto; }
            h1 { text-align: center; }
            select, button { padding: 10px; font-size: 16px; cursor: pointer; background-color: #333; color: #0f0; border: 1px solid #0f0; margin-right: 10px; }
            #output-log { background-color: #111; border: 1px solid #0f0; padding: 10px; height: 60vh; overflow-y: scroll; margin-top: 20px; white-space: pre-wrap; word-wrap: break-word; }
            #output-log::-webkit-scrollbar { width: 8px; }
            #output-log::-webkit-scrollbar-thumb { background: #0f0; border-radius: 4px; }
            #output-log::-webkit-scrollbar-track { background: #111; }
            .log-line { border-left: 2px solid #0f0; padding-left: 10px; margin-bottom: 5px; }
            .type-round { color: #fff; font-size: 1.2em; border-left: none; }
            .type-attacker { color: #f00; }
            .type-defender { color: #0f0; }
            .type-compromised { color: #ff0; animation: blink-animation 1s steps(5, start) infinite; }
            .type-failed { color: #ff0; }
            .progress-container { width: 100%; background-color: #333; border: 1px solid #0f0; margin-top: 10px; }
            .progress-bar { width: 0%; height: 20px; background-color: #0f0; transition: width 0.5s; }
            @keyframes blink-animation { to { visibility: hidden; } }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>AI Attacker vs Defender</h1>
            <p>Select a scenario and click start to begin the simulation.</p>
            <select id="scenario-select">
                <option value="sql_injection">SQL Injection</option>
                <option value="xss">Cross-Site Scripting (XSS)</option>
                <option value="brute_force">Brute Force</option>
                <option value="pathtraversal">Path Traversal</option>
                <option value="ddos">DDoS Attack</option>
            </select>
            <button id="start-button">Start Simulation</button>
            <div id="output-log"></div>
            <div class="progress-container"><div id="progress-bar" class="progress-bar"></div></div>
        </div>
        <script>
            document.getElementById('start-button').addEventListener('click', function() {
                var scenario = document.getElementById('scenario-select').value;
                var outputLog = document.getElementById('output-log');
                outputLog.innerHTML = '';
                var source = new EventSource("/stream?scenario=" + scenario);
                var round = 0;
                var progressBar = document.getElementById('progress-bar');
                
                source.onmessage = function(event) {
                    var data = JSON.parse(event.data);
                    if (data.log.startsWith("--- Round")) {
                        round++;
                        progressBar.style.width = (round / 5) * 100 + "%";
                    }
                    if (data.log === "END_OF_SIMULATION") {
                        source.close();
                        document.getElementById('start-button').disabled = false;
                        document.getElementById('start-button').textContent = "Restart Simulation";
                    } else {
                        var logElement = document.createElement('div');
                        logElement.textContent = data.log;
                        if (data.type) { logElement.classList.add('type-' + data.type); }
                        outputLog.appendChild(logElement);
                        outputLog.scrollTop = outputLog.scrollHeight;
                    }
                };
                document.getElementById('start-button').disabled = true;
                document.getElementById('start-button').textContent = "Simulation in Progress...";
            });
        </script>
    </body>
    </html>
    """)

@app.route('/stream')
def stream_events():
    scenario = request.args.get('scenario')
    return Response(generate_events(scenario), mimetype="text/event-stream")

if __name__ == '__main__':
    load_patches()
    setup_database()
    app.run(host='0.0.0.0', port=5002)