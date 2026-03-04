# Getting Started: Building Clinkz with Claude Code

## Step 0: Prerequisites

Make sure you have these installed:

```bash
# Check Python
python3 --version  # Need 3.12+

# Check Docker
docker --version
docker compose version

# Check Claude Code
claude --version

# Check Node.js (needed for Claude Code)
node --version  # Need 18+
```

If Claude Code isn't installed yet:
```bash
# macOS
brew install anthropic-ai/tap/claude-code

# Or via npm (deprecated but works)
npm install -g @anthropic-ai/claude-code
```

---

## Step 1: Create the Project

```bash
# Create project directory
mkdir clinkz && cd clinkz

# Initialize git
git init

# Copy the CLAUDE.md file into the project root
# (use the CLAUDE.md file provided with this guide)
cp /path/to/CLAUDE.md .

# Start Claude Code
claude
```

---

## Step 2: First Claude Code Session — Project Scaffold

Once inside Claude Code, give it this first prompt:

```
Read the CLAUDE.md file. Set up the complete project scaffold:
1. Create the directory structure exactly as documented (including the llm/ directory)
2. Create pyproject.toml with all dependencies (openai, anthropic, google-generativeai, 
   ollama, langgraph, pydantic, typer, aiohttp, aiosqlite, weasyprint, jinja2, ruff, 
   pytest, pytest-asyncio, python-dotenv)
3. Create the LLM abstraction layer FIRST:
   - llm/base.py: Abstract LLMClient with methods reason(), research(), generate_text()
   - llm/openai_client.py: OpenAI implementation (GPT-4o with tool calling)
   - llm/factory.py: Returns correct client based on LLM_PROVIDER env var
   - Don't implement anthropic/gemini/ollama clients yet, just leave stubs
4. Create the base classes: tools/base.py (ToolBase abstract class), agents/base.py 
   (BaseAgent with ReAct loop skeleton), state.py (SQLite state store with tables for 
   targets, findings, actions, attempts), models/ (all Pydantic models), and config.py
5. Create a basic cli.py with Typer that has "scan", "recon", "crawl", "exploit", 
   "report" commands (stubs are fine)
6. Create a .env.example with LLM_PROVIDER=openai and API key placeholders
7. Create a .gitignore for Python projects
Don't implement the agent logic yet — just the scaffolding and base classes.
```

**Review what Claude creates**, then approve the file changes.

---

## Step 3: Docker Environment for Security Tools

Next prompt in the same session (or start a new one with `/clear`):

```
Create the Docker setup for our security tools:
1. docker/Dockerfile.tools — base image (Kali Linux or Ubuntu) with: nmap, nikto, ffuf, 
   nuclei, sqlmap, subfinder, httpx, katana, whatweb, wafw00f, gobuster, feroxbuster, 
   amass, sslyze, arjun, dalfox, gospider
2. docker/docker-compose.yml with:
   - Our tools container
   - OWASP Juice Shop (bkimminich/juice-shop) on port 3000
   - DVWA (vulnerables/web-dvwa) on port 8080
3. A simple test script that verifies all tools are installed correctly
```

---

## Step 4: Build the First Tool Wrapper (Nmap)

This is the most important early milestone. New session:

```
Let's build the Nmap tool wrapper. This is the template all other tool wrappers will follow.

1. Implement tools/nmap.py inheriting from ToolBase:
   - get_schema(): returns the JSON schema for Nmap parameters (target, ports, scan_type, 
     scripts, timing)
   - validate_input(): checks target is within scope, validates parameters
   - execute(): runs Nmap in the Docker container with -oX for XML output, handles 
     timeouts
   - parse_output(): parses Nmap XML into Pydantic models (Host, Port, Service with 
     version info)
2. Create tests/fixtures/nmap_sample_output.xml with realistic Nmap output
3. Create tests/test_tools/test_nmap.py with unit tests for parsing and validation
4. Make sure the wrapper enforces scope — if someone passes a target not in the scope 
   config, it should raise a ScopeViolationError

Run the tests to verify everything works.
```

---

## Step 5: Build the ReAct Agent Loop

```
Now let's build the core agent reasoning loop in agents/base.py:

1. Implement the ReAct loop: Observe → Reason → Act → Reflect
2. The "Reason" step should call the LLM via our abstract LLMClient (from llm/base.py), 
   passing the current state and available tools. NEVER import openai or any SDK directly.
   Use: client = LLMClientFactory.create() from llm/factory.py
3. The "Act" step should dispatch to the appropriate tool wrapper
4. The "Reflect" step should evaluate the tool output and update the state store
5. Include proper error handling: tool failures, LLM errors, timeout handling
6. Add structured logging for every step of the loop
7. Add token usage tracking for cost monitoring

Write a simple integration test: give the agent Nmap as its only tool, point it at 
localhost, and verify it runs a scan and stores results in the state store.
```

---

## General Claude Code Workflow Tips

### Start every session right
```bash
cd clinkz
claude
```
Claude Code automatically reads your CLAUDE.md for project context.

### Use `/clear` between tasks
Don't let context from building the Nmap wrapper bleed into building the Recon Agent. 
Start fresh for each major component.

### Use Plan Mode for complex tasks
Press `Shift+Tab` twice to enter Plan Mode. Use it before building any agent or 
complex component. Ask Claude to create a plan, review it, then switch to implementation.

### Branch per feature
```
Create a new git branch called "feat/nmap-wrapper" and work on it.
```
Always ask Claude to branch. Never work on main.

### Test as you go
End every session with:
```
Run the tests for what we just built and fix any failures.
```

### Update CLAUDE.md as you learn
When Claude makes a mistake or you discover a pattern that works well, add it:
```
Add to CLAUDE.md: "When creating tool wrappers, always include a 
timeout parameter with a default of 300 seconds."
```

### Save your prompts
If a prompt works really well, save it as a custom command:
```bash
mkdir -p .claude/commands
# Then ask Claude to save useful prompts there
```

---

## Development Order (Full Build Sequence)

After the foundation (Steps 1-5), build in this order:

| Week  | What to Build | Key Prompt Pattern |
|-------|--------------|-------------------|
| W1-2  | Foundation + Nmap wrapper + ReAct loop | Steps 1-5 above |
| W3    | Remaining recon tools (subfinder, httpx, whatweb, nikto, sslyze, wafw00f) | "Build the {tool} wrapper following the exact same pattern as nmap.py" |
| W4    | Recon Agent (agents/recon.py) | "Build the Recon Agent that uses all recon tools to enumerate a target. Test against Juice Shop." |
| W5    | Crawl tools (katana, ffuf, gobuster, arjun) | Same pattern as recon tools |
| W6    | Crawl Agent (agents/crawl.py) | "Build the Crawl Agent. Input: recon results. Output: attack surface map." |
| W7    | Exploit tools (sqlmap, nuclei, dalfox) + runtime research | "Build the runtime research module that searches for CVEs and exploits via web search" |
| W8-9  | Exploit Agent (agents/exploit.py) | "Build the Exploit Agent with research-then-attack cycle" |
| W10   | Critic Agent + finding validation | "Build the Critic Agent that validates findings and scores CVSS" |
| W11   | Report Agent + PDF/HTML templates | "Build the report generation pipeline with Jinja2 templates" |
| W12   | Orchestrator + full pipeline integration | "Wire everything together: scope → recon → crawl → exploit → report" |
| W13-14| Hardening + testing against multiple targets | "Run against Juice Shop, DVWA, WebGoat. Fix failures." |
| W15-16| Polish + docs | "Write comprehensive README and setup documentation" |
