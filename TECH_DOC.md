# ⚙️ Technical Documentation

This document provides a detailed overview of the core architectural and implementation decisions for the AI Attacker vs. Defender project.

## 🏛️ Architecture

The project follows a single-file, client-server architecture built on the Flask web framework.

- **Backend (Python):** `app.py` serves as a full-stack backend. It manages the simulation logic, AI interactions, and serves the static HTML/CSS/JS frontend.
- **Frontend (HTML/JS/CSS):** The user interface is a single HTML template rendered by Flask. JavaScript handles user events (button clicks) and listens for real-time updates from the backend using **Server-Sent Events (SSE)**.

## 🧠 AI Logic

Both the attacker and defender agents are powered by the Google Gemini API. The intelligence of these agents is primarily a function of sophisticated **prompt engineering** rather than complex programming.

- **Attacker Agent (Red AI):** The attacker is given a persona as a "penetration tester" and is instructed to generate malicious payloads in a JSON format. It receives feedback from the simulation (e.g., "Attack failed," "Server response was 'Too many requests'"), which it uses to inform its next move.
- **Defender Agent (Blue AI):** The defender is a "security analyst." It receives a log entry from the simulation and is prompted to provide an analysis, identify the vulnerability type, and suggest a mitigation, all in a structured JSON format.

## 🛡️ Evolving Defense

The core innovation of this project is its persistent defense mechanism.

1.  **The `patches.json` file:** The defender's memory is stored in a simple JSON file. This file contains boolean flags for each vulnerability (e.g., `"xss_patched": false`).
2.  **Detection & Patching:** When the defender's AI successfully analyzes an attack, the `app.py` script updates the corresponding flag in `patches.json` from `false` to `true`.
3.  **Persistent Evasion:** On subsequent simulation runs, the backend reads `patches.json` and, if a patch is applied, it serves the secure, non-vulnerable code instead of the original code, effectively "patching" the system.

## 💥 Vulnerability Simulation

Each attack scenario is simulated by a dedicated Flask route that contains a specific vulnerability.

- **SQL Injection (`/login`):** An f-string is used to directly insert user input into an SQL query, making it susceptible to injection attacks.
- **XSS (`/search`):** The user input from a search query is directly reflected in the HTML without sanitization, allowing malicious script execution.
- **Brute Force (`/bruteforce_login`):** The login route lacks a rate-limiting feature, allowing an attacker to send an unlimited number of login attempts.
- **DDoS (`/overload`):** A request counter is implemented to simulate the server being overwhelmed after a certain number of requests.
- **Path Traversal (`/file`):** The server trusts user input for a file path, allowing an attacker to access restricted files.

## 🛣️ Future Improvements

- **Polymorphic Attacker:** Implement a more advanced attacker AI that uses detailed server responses to generate novel, more complex payloads that are harder to detect.
- **Dynamic Defense:** Allow the defender to generate and implement the mitigation code itself, rather than simply flipping a boolean flag.
- **New Scenarios:** Add more vulnerabilities, such as Command Injection or Server-Side Request Forgery (SSRF).
