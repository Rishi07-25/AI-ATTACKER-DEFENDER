# 🤖 AI Attacker vs. Defender Simulation

A dynamic, web-based simulation where two AI agents—an attacker and a defender—are locked in a continuous battle. The attacker attempts to exploit vulnerabilities in a web service, while the defender analyzes the attacks and evolves its defenses to patch the system in real time.

## ✨ Features

- **Interactive Web Interface:** A real-time, terminal-style web page to visualize the simulation.
- **Evolving AI Agents:** The attacker AI adapts its payloads based on a target's response, while the defender AI learns from successful attacks to permanently patch vulnerabilities.
- **Multiple Attack Scenarios:** Includes simulations for common web attacks such as SQL Injection, Cross-Site Scripting (XSS), Brute Force, DDoS, and Path Traversal.
- **Persistent Defense:** The defender's patches are saved, so a patched vulnerability remains fixed on subsequent simulation runs.
- **Ethical and Educational:** Provides a safe and clear demonstration of web vulnerabilities and modern security principles.

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- A Google Gemini API Key

### Installation

1.  Clone this repository to your local machine:
    `git clone https://github.com/karambur-shashank-eb/ai-attacker-defender.git`

2.  Navigate into the project directory:
    `cd ai-attacker-defender`

3.  Set up a virtual environment and install the required dependencies:
    `python3 -m venv venv`
    `source venv/bin/activate` (macOS/Linux) or `venv\Scripts\activate` (Windows)
    `pip install -r requirements.txt`

    *(Note: You will need to create a `requirements.txt` file by running `pip freeze > requirements.txt` after installing your dependencies).*

### Usage

1.  **Add Your API Key:** Open `app.py` and replace `"YOUR_API_KEY_HERE"` with your actual Google Gemini API key. **Do not share your key!**

2.  **Run the Simulation:**
    `python3 app.py`

3.  **Open in Browser:** Navigate to `http://127.0.0.1:5002` in your web browser. Select a scenario from the dropdown and click "Start Simulation."

## 📄 Project Structure

- `app.py`: The main application file containing all the server logic, AI agents, and web interface.
- `database.db`: A local SQLite database for the SQL Injection demo.
- `patches.json`: The defender's "memory" file, which stores information about patched vulnerabilities.
- `.gitignore`: Ensures sensitive files are not uploaded to GitHub.
