# AutoRecon-AI

An intelligent, AI-assisted reconnaissance tool designed for Capture The Flag (CTF) challenges. This Python script automates the initial enumeration phase by chaining tools (Nmap, Gobuster, Nikto) dynamically based on OpenAI's real-time analysis of the target.

## Features
- **Smart Target Resolution:** Automatically detects HTTP redirects (Virtual Hosts) and offers to update your `/etc/hosts` file.
- **Dynamic Tool Execution:** Uses `gpt-4o-mini` to analyze Nmap results and suggest the best next steps (e.g., Gobuster, Nikto).
- **Human-in-the-loop:** Always asks for user confirmation before executing potentially aggressive scans.
- **Deep Analysis (Phase 2):** Parses the output of the executed tools (like discovering a `/vendor` folder) to suggest advanced exploitation vectors.
- **Safe Interruption:** Built-in `Ctrl+C` handling allows you to cancel slow scans (like Nikto) without crashing the program, saving partial results for the AI.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Augustin-Br/ai-scanner.git
   cd ctf-ai-scanner
   ```

2. Create a virtual environment and install dependencies:
    ```bash
    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    ```

3. Configure your API key:

Create a `.env` file in the root directory and add your OpenAI API key:
```bash
OPENAI_API_KEY=sk-...
```

## Usage

Run the script with Python (sudo privileges might be requested if a VHost needs to be added to `/etc/hosts`):

```bash
python main.py
```
