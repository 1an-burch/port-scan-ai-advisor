# Port Scan AI Advisor

SUMMER 2026:
A small Python tool that checks a host (Metasploitable) for a few common open ports, then prints a defensive security checklist with a short explanation of each risk from a local Llama 3 model running through [Ollama](https://ollama.com).

## How it works

1. Scans a short list of TCP ports (21, 22, 80) with a simple connect check and a 1-second timeout.
2. For each open port, looks up a reference entry: service name, main risk, and suggested hardening commands.
3. Asks the local Llama 3 model for a 2-3 sentence explanation aimed at a junior sysadmin. If Ollama isn't available, it falls back to a generic summary instead of crashing.
4. Prints a checklist.

**The AI output is advisory only.** It is never parsed into commands or executed. The suggested commands come from a fixed lookup table in the code, and the tool prints them for you to review and run yourself. Nothing is changed on the target.

## Files

- `main2.py`: current version
- `main.py`: the original first prototype

## Setup

Requires Python 3 and [Ollama](https://ollama.com) installed locally.

```bash
pip install -r requirements.txt
ollama pull llama3
```

## Usage

The target IP is set at the top of the script. Edit `target_ip` in `main2.py` to point at a machine you own, then run:

```bash
python main2.py
```
