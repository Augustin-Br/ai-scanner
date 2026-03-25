# AutoRecon-AI (LangGraph Edition)

An intelligent, stateful AI-assisted reconnaissance tool designed for Capture The Flag (CTF) challenges. This tool automates the initial enumeration phase by chaining modern tools (Nmap, Gobuster, Nuclei, WhatWeb, Ffuf) dynamically, powered by OpenAI's GPT-4o-mini and LangGraph.

## Architecture & Features

This tool uses a **ReAct (Reason & Act) Agent architecture** built with LangGraph, moving away from linear scripting to a fully stateful, cyclic workflow:

- **Stateful Memory:** The agent maintains a persistent `AgentState` containing the target information, Nmap results, and cumulative outputs of all executed tools.
- **Dynamic Pivoting (Phase 1 & 2):** The AI autonomously decides when to transition from basic enumeration (WhatWeb, Nuclei, Gobuster) to advanced pivoting (Subdomain enumeration with Ffuf, Extension fuzzing).
- **Python Guardrails (Strict Anti-Loop):** Implements deterministic Python-side filtering to prevent the LLM from hallucinating command variations or getting stuck in infinite execution loops.
- **Human-in-the-loop (HITL):** Uses LangGraph Checkpointers to pause execution before running any Bash command, requiring explicit user approval.
- **Smart Target Resolution:** Automatically detects HTTP redirects (Virtual Hosts) and offers to securely update your `/etc/hosts` file.

## Requirements & Prerequisites

The agent relies on standard Kali/Parrot OS security tools. Ensure the following are installed and in your system's PATH:
- `nmap`
- `whatweb`
- `nuclei`
- `gobuster`
- `ffuf`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Augustin-Br/autorecon-ai.git
   cd autorecon-ai
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