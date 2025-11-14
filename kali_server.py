#!/usr/bin/env python3

import argparse
import logging
import os
import subprocess
import sys
import threading
import traceback
import shlex
from typing import Dict, Any
from flask import Flask, request, jsonify
import re
import tempfile  
from typing import Dict, Any
import shutil

# ANSI escape sequence regex (covers common CSI sequences)
_ANSI_RE = re.compile(r'\x1B\[[0-9;?]*[ -/]*[@-~]')

# Maximum number of characters to keep in stdout/stderr to avoid huge payloads to the LLM
_MAX_OUTPUT_LEN = 20000
# ----------------------------- Logging ----------------------------- #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# ------------------------- Configuration -------------------------- #
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 600 


app = Flask(__name__)

# ------------------------ Helpers ------------------------ #
def q(s: str) -> str:
    """Shell-quote arguments to avoid injection."""
    return shlex.quote(str(s)) if s else ""

# ------------------------ Command Executor ------------------------ #
# ------------------------ Command Executor (fixed) ------------------------ #
class CommandExecutor:
    """
    Execute shell commands or argv lists with timeout and streaming output.
    Accepts either:
      - a single string (will run with shell=True)
      - a list/tuple of argv tokens (will run with shell=False)
    """

    def __init__(self, command, timeout: int = COMMAND_TIMEOUT):
        # command may be a str or a list/tuple
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.return_code = None
        self.timed_out = False

    def _read_stream(self, stream, buffer_name: str):
        # read lines until EOF
        buf = []
        try:
            for line in iter(stream.readline, ''):
                if line == '':
                    break
                buf.append(line)
        except Exception:
            # fallback: read rest
            try:
                remaining = stream.read()
                if remaining:
                    buf.append(remaining)
            except Exception:
                pass
        setattr(self, buffer_name, "".join(buf))

    def execute(self) -> Dict[str, Any]:
        logger.info(f"Executing command: {self.command!r} (timeout={self.timeout}s)")
        try:
            # Decide whether to use shell
            use_shell = isinstance(self.command, str)

            # If user passed a list/tuple, call Popen with that list (shell=False)
            popen_args = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "text": True,
                "bufsize": 1
            }
            if use_shell:
                popen_args["shell"] = True
                popen_target = self.command
            else:
                popen_args["shell"] = False
                popen_target = list(self.command)  # ensure list

            self.process = subprocess.Popen(popen_target, **popen_args)

            threads = [
                threading.Thread(target=self._read_stream, args=(self.process.stdout, "stdout_data"), daemon=True),
                threading.Thread(target=self._read_stream, args=(self.process.stderr, "stderr_data"), daemon=True),
            ]
            for t in threads:
                t.start()

            try:
                self.return_code = self.process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} sec, terminating.")
                try:
                    self.process.terminate()
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                self.return_code = -1

            for t in threads:
                t.join(timeout=1)

            success = (self.return_code == 0)
            partial = self.timed_out and (bool(self.stdout_data or self.stderr_data))

            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "exit_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": partial
            }

        except Exception as e:
            logger.error(f"Execution error: {e}")
            logger.debug(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "exit_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command) -> Dict[str, Any]:
    """
    Run the command via CommandExecutor and return a sanitized JSON-friendly dict.
    Accepts either a string or a list/tuple of args.
    """
    executor = CommandExecutor(command)
    result = executor.execute() or {}

    raw_stdout = result.get("stdout", "") or ""
    raw_stderr = result.get("stderr", "") or ""

    try:
        clean_stdout = _ANSI_RE.sub("", raw_stdout)
        clean_stderr = _ANSI_RE.sub("", raw_stderr)
    except Exception:
        clean_stdout = raw_stdout
        clean_stderr = raw_stderr

    def _truncate(s: str) -> str:
        if not s:
            return s
        if len(s) > _MAX_OUTPUT_LEN:
            head = s[:_MAX_OUTPUT_LEN]
            return head + "\n\n[TRUNCATED - original length: {}]".format(len(s))
        return s

    clean_stdout = _truncate(clean_stdout)
    clean_stderr = _truncate(clean_stderr)

    safe_result = dict(result)
    safe_result["stdout"] = clean_stdout
    safe_result["stderr"] = clean_stderr

    # Normalize keys
    if "return_code" not in safe_result and "exit_code" in safe_result:
        safe_result["return_code"] = safe_result.get("exit_code")
    safe_result["success"] = bool(safe_result.get("return_code") == 0)

    return safe_result



# --------------------------- Generic API -------------------------- #
@app.route("/api/command", methods=["POST"])
def generic_command():
    params = request.json or {}
    command = params.get("command")
    if not command:
        return jsonify({"error": "Command parameter is required"}), 400
    return jsonify(execute_command(command))

# --------------------------- Tool Endpoints ----------------------- #
@app.route("/api/tools/nmap", methods=["POST"])
def nmap_tool():
    p = request.json or {}
    cmd = f"nmap {p.get('scan_type','-sV')} {p.get('ports','')} {p.get('additional_args','')} {q(p.get('target'))}"
    return jsonify(execute_command(cmd))

@app.route("/api/tools/nessuscli", methods=["POST"])
def nessuscli_tool():
    """
    Execute nessuscli command on the Kali server.

    Expected JSON body:
    {
        "command": "agent",
        "args": "--status"
    }
    """
    p = request.json or {}
    base_cmd = "/opt/nessus/sbin/nessuscli"

    # Befehl zusammenbauen
    cmd = f"{base_cmd} {p.get('command','')} {p.get('args','')}"

    return jsonify(execute_command(cmd))

@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster_tool():
    p = request.json or {}
    cmd = f"gobuster {q(p.get('mode','dir'))} -u {q(p.get('url'))} -w {q(p.get('wordlist','/usr/share/wordlists/dirb/common.txt'))} {p.get('additional_args','')}"
    return jsonify(execute_command(cmd))

@app.route("/api/tools/dirb", methods=["POST"])
def dirb_tool():
    p = request.json or {}
    cmd = f"dirb {q(p.get('url'))} {q(p.get('wordlist','/usr/share/wordlists/dirb/common.txt'))} {p.get('additional_args','')}"
    return jsonify(execute_command(cmd))

@app.route("/api/tools/nikto", methods=["POST"])
def nikto_tool():
    p = request.json or {}
    cmd = f"nikto -h {q(p.get('target'))} {p.get('additional_args','')}"
    return jsonify(execute_command(cmd))

@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap_tool():
    try:
        p = request.json or {}
        url = (p.get("url") or "").strip() or "http://127.0.0.1/vulnerabilities/sqli/?id=1&Submit=Submit"
        data = (p.get("data") or "").strip()
        cookie = (p.get("cookie") or "").strip()
        additional_args = (p.get("additional_args") or "").strip()
        timeout = int(p.get("timeout", COMMAND_TIMEOUT))
        risk = int(p.get("risk", 1))
        level = int(p.get("level", 1))

        import shlex

        args = ["sqlmap", "-u", url, "--batch", "--threads=5", "--random-agent",
                f"--risk={risk}", f"--level={level}"]
        if data:
            args.append(f"--data={data}")
        if cookie:
            args.append(f"--cookie={cookie}")

        if additional_args:
            # parse flags safely, do NOT quote flags; let shlex split into proper args
            args.extend(shlex.split(additional_args))

        executor = CommandExecutor(args, timeout=timeout)  # expect executor to accept list
        result = executor.execute()
        result["command"] = " ".join(shlex.quote(a) for a in args)
        result["command_args"] = args
        result["success"] = (result.get("exit_code", 1) == 0) if "success" not in result else result["success"]
        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "error": str(e), "stdout": "", "stderr": "", "timed_out": False})
@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit_tool():
    import shlex

    p = request.json or {}
    module = (p.get("module") or "").strip()
    options = p.get("options") or {}

    if not module:
        return jsonify({"error": "Missing Metasploit module", "success": False}), 400

    try:
        timeout = int(p.get("timeout", max(COMMAND_TIMEOUT, 1800)))  # allow long default
    except Exception:
        timeout = max(COMMAND_TIMEOUT, 1800)

    # Build msfconsole command via -x (quoted single string), but pass as list to Popen
    # so we avoid shell=True when not needed. msfconsole executable and -x argument remain tokens.
    lines = [f"use {module}"]
    for k, v in (options or {}).items():
        key = str(k).strip()
        # remove newlines in values to avoid accidental multi-line injection
        val = str(v).replace("\n", " ").strip()
        if key and val:
            lines.append(f"set {key} {val}")

    # ensure msfconsole exits after run
    lines.append("set EXITONSESSION true")
    lines.append("run")
    lines.append("exit")

    cmd_str = "; ".join(lines)

    # Build args list (no shell): msfconsole -q -x "cmd1; cmd2; ..."
    args = ["msfconsole", "-q", "-x", cmd_str]

    executor = CommandExecutor(args, timeout=timeout)
    result = executor.execute()

    # Normalize metadata and response
    result = result or {}
    result["command"] = " ".join(shlex.quote(a) for a in args)
    result["command_args"] = args
    result["success"] = bool(result.get("return_code") == 0)

    return jsonify(result)

@app.route("/api/tools/hydra", methods=["POST"])
def hydra_tool():
    try:
        import shlex
        p = request.json or {}

        target = (p.get("target") or "127.0.0.1").strip()
        service = (p.get("service") or "ssh").strip()
        username = (p.get("username") or "").strip()
        username_file = (p.get("username_file") or "").strip()
        password = (p.get("password") or "").strip()
        password_file = (p.get("password_file") or "").strip()
        additional_args = (p.get("additional_args") or "").strip()
        timeout = int(p.get("timeout", COMMAND_TIMEOUT))

        args = ["hydra"]

        if username_file:
            args += ["-L", username_file]
        elif username:
            args += ["-l", username]
        else:
            args += ["-l", "admin"]

        if password_file:
            args += ["-P", password_file]
        elif password:
            args += ["-p", password]
        else:
            args += ["-p", "admin"]

        # Threading and quick-exit
        args += ["-t", "4", "-f"]

        # Optional port via service if numeric
        if service.isdigit():
            args += ["-s", service]
            service_name = "ssh"  # sensible default
        else:
            service_name = service

        # For HTTP forms, ensure proper module syntax (caller should pass it via service)
        # e.g., service="http-post-form", additional_args=":/login:username=^USER^&password=^PASS^:F=Invalid"
        args += [target, service_name]

        if additional_args:
            args.extend(shlex.split(additional_args))

        executor = CommandExecutor(args, timeout=timeout)
        result = executor.execute()
        result["command"] = " ".join(shlex.quote(a) for a in args)
        result["command_args"] = args
        result["success"] = (result.get("exit_code", 1) == 0)
        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "error": str(e), "stdout": "", "stderr": "", "timed_out": False})


@app.route("/api/tools/john", methods=["POST"])
def john_tool():
    try:
        import shlex
        p = request.json or {}

        # ----- Gather inputs with safe defaults -----
        requested_format = (p.get("format") or "").strip()  # e.g., "raw-md5", "raw-sha1", "nt"
        wordlist = (p.get("wordlist") or "/usr/share/wordlists/rockyou.txt").strip()
        hash_file = (p.get("hash_file") or "").strip()
        additional_args = (p.get("additional_args") or "").strip()
        timeout = int(p.get("timeout", COMMAND_TIMEOUT))

        # ----- Ensure wordlist exists, or create a tiny fallback -----
        if not os.path.exists(wordlist):
            try:
                # create small fallback wordlist
                wordlist = "/tmp/john_default_wordlist.txt"
                if not os.path.exists(wordlist):
                    with open(wordlist, "w") as f:
                        f.write("password\nadmin\n123456\n")
            except Exception:
                # If file creation fails, fallback to empty string to let john error gracefully
                wordlist = ""

        # ----- Ensure hash_file exists, or create a tiny default hash file -----
        fallback_format = None
        if not hash_file or not os.path.exists(hash_file):
            # create a default MD5 hash file for 'password' (hash: 5f4dcc3b5aa765d61d8327deb882cf99)
            hash_file = "/tmp/john_default_hashes.txt"
            if not os.path.exists(hash_file):
                try:
                    with open(hash_file, "w") as f:
                        # john accepts plain hashes; choosing raw-md5 as default
                        f.write("5f4dcc3b5aa765d61d8327deb882cf99\n")
                    fallback_format = "raw-md5"
                except Exception:
                    hash_file = ""  # let john handle if creation fails

        # If user didn't request a format but we created a fallback hash, set the format
        fmt_flag = ""
        if requested_format:
            fmt_flag = f"--format={q(requested_format)}"
        elif fallback_format:
            fmt_flag = f"--format={q(fallback_format)}"
        else:
            # leave fmt_flag empty (john will try to auto-detect)
            fmt_flag = ""

        # ----- Build command parts safely (quote tokens) -----
        parts = ["john"]
        if fmt_flag:
            parts.append(fmt_flag)

        if wordlist:
            parts.append(f"--wordlist={q(wordlist)}")

        if hash_file:
            parts.append(q(hash_file))
        else:
            # If no hash_file, provide something harmless so the command runs but john will error out
            parts.append(q("/dev/null"))

        # Safely parse and append additional_args (tokenize then quote each token)
        if additional_args:
            safe_additional = additional_args.replace("\n", " ").replace(";", " ")
            try:
                tokens = shlex.split(safe_additional)
            except ValueError:
                parts.append(q(safe_additional))
            else:
                parts.extend(q(t) for t in tokens)

        # Join into final command string for current executor design (shell=True)
        cmd = " ".join(parts)

        # ----- Execute with configurable timeout -----
        executor = CommandExecutor(cmd, timeout=timeout)
        result = executor.execute()

        # Add helpful context to returned JSON
        result["command_executed"] = cmd
        result["success"] = result.get("success", False)
        return jsonify(result)

    except Exception as e:
        # Never crash; always return useful JSON
        return jsonify({
            "success": False,
            "error": str(e),
            "stdout": "",
            "stderr": "",
            "timed_out": False
        })
# --------------------------- WPScan (LLM-friendly) -------------------------- #
@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan_tool():
    """
    WPScan endpoint returns structured, concise output for LLM consumption.
    """
    p = request.json or {}
    url = (p.get("url") or "").strip()
    additional_args = (p.get("additional_args") or "").strip()
    timeout = int(p.get("timeout", 300))

    if not url:
        return jsonify({"success": False, "error": "missing url"}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    wpscan_bin = shutil.which("wpscan") or shutil.which("/usr/bin/wpscan")
    if not wpscan_bin:
        return jsonify({"success": False, "error": "wpscan not found"}), 500

    api_token = os.environ.get("WPSCAN_API_TOKEN", "").strip()
    if not api_token:
        return jsonify({"success": False, "error": "WPSCAN_API_TOKEN not set"}), 500

    # Temporary JSON output
    tmp = tempfile.NamedTemporaryFile(prefix="wpscan_", suffix=".json", delete=False)
    tmp_path = tmp.name
    tmp.close()

    args = [wpscan_bin, "--url", url, "--format", "json", "--output", tmp_path, "--api-token", api_token]
    if additional_args:
        import shlex as _shlex
        try:
            args += _shlex.split(additional_args)
        except Exception:
            args.append(additional_args)

    try:
        cp = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return jsonify({"success": False, "error": "timeout"}), 504
    except Exception as e:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return jsonify({"success": False, "error": f"execution error: {e}"}), 500

    # Read and parse WPScan JSON
    wpscan_json = {}
    try:
        with open(tmp_path, "r", encoding="utf-8") as f:
            import json
            wpscan_json = json.load(f)
    except Exception as e:
        raw_stdout = cp.stdout[:20000] if cp.stdout else ""
        raw_stderr = cp.stderr[:20000] if cp.stderr else ""
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return jsonify({
            "success": False,
            "error": f"failed to parse wpscan output: {e}",
            "stdout": raw_stdout,
            "stderr": raw_stderr
        }), 500
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    # ---------------- Build LLM-friendly summary ---------------- #
    summary = {
        "target_url": wpscan_json.get("target_url"),
        "wordpress_version": wpscan_json.get("version", {}).get("number"),
        "version_status": wpscan_json.get("version", {}).get("status"),
        "main_theme": {
            "name": wpscan_json.get("main_theme", {}).get("slug"),
            "version": wpscan_json.get("main_theme", {}).get("version", {}).get("number"),
            "vulnerabilities": wpscan_json.get("main_theme", {}).get("vulnerabilities", [])
        },
        "plugins": [],
        "interesting_findings": []
    }

    # Plugins
    for plugin_name, plugin_data in wpscan_json.get("plugins", {}).items():
        summary["plugins"].append({
            "name": plugin_name,
            "version": plugin_data.get("version", {}).get("number"),
            "outdated": plugin_data.get("outdated"),
            "vulnerabilities": plugin_data.get("vulnerabilities", [])
        })

    # Interesting findings
    for finding in wpscan_json.get("interesting_findings", []):
        summary["interesting_findings"].append({
            "url": finding.get("url"),
            "type": finding.get("type"),
            "description": finding.get("to_s"),
            "confidence": finding.get("confidence")
        })

    return jsonify({
        "success": True,
        "url": url,
        "return_code": cp.returncode,
        "summary": summary,
        "raw_json": wpscan_json
    })
@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux_tool():
    import shlex
    p = request.json or {}
    target = (p.get("target") or "").strip()
    additional_args = (p.get("additional_args") or "").strip()
    try:
        timeout = int(p.get("timeout", COMMAND_TIMEOUT))
    except Exception:
        timeout = COMMAND_TIMEOUT

    if not target:
        return jsonify({"success": False, "error": "Missing target parameter"}), 400

    # Find enum4linux in PATH (best-effort)
    which_res = execute_command(["which", "enum4linux"])
    enum4_path = None
    if which_res.get("return_code") == 0 and which_res.get("stdout"):
        enum4_path = which_res["stdout"].strip().splitlines()[-1]
    else:
        # fallback common locations
        for path in ["/usr/bin/enum4linux", "/usr/share/enum4linux/enum4linux.pl", "/usr/local/bin/enum4linux"]:
            if os.path.exists(path):
                enum4_path = path
                break

    if not enum4_path or not os.path.exists(enum4_path):
        return jsonify({"success": False, "error": "enum4linux not found on server. Install it and ensure it's in PATH."}), 500

    # Build safe argv list
    args = [enum4_path]

    if additional_args:
        try:
            args.extend(shlex.split(additional_args))
        except ValueError:
            args.append(additional_args)

    args.append(target)

    # Execute as argv list (no shell) with configurable timeout
    result = execute_command(args if isinstance(args, (list, tuple)) else " ".join(args))
    result = result or {}
    result["command_args"] = args
    try:
        result["command"] = " ".join(shlex.quote(a) for a in args) if isinstance(args, (list, tuple)) else str(args)
    except Exception:
        result["command"] = str(args)

    # ----------------- New Parsing for LLM ----------------- #
    # Split stdout into lines and create structured output
    stdout = result.get("stdout", "")
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    parsed_output = {"lines": lines}

    # Keep stderr separate
    stderr = result.get("stderr", "").strip()

    return jsonify({
        "success": bool(lines),
        "command": result.get("command", ""),
        "command_args": result.get("command_args", []),
        "stdout": parsed_output,
        "stderr": stderr,
        "return_code": result.get("return_code", -1)
    })



# --------------------------- Health Check ------------------------- #
@app.route("/health", methods=["GET"])
def health_check():
    essential = ["nmap","gobuster","dirb","nikto","sqlmap","msfconsole","hydra","john","wpscan","enum4linux"]
    status = {}
    for tool in essential:
        result = execute_command(f"which {q(tool)}")
        status[tool] = result.get("success", False) and result.get("return_code") == 0
    return jsonify({
        "status": "healthy" if all(status.values()) else "degraded",
        "tools_status": status,
        "all_essential_tools_available": all(status.values())
    })

# --------------------------- Main --------------------------- #
def parse_args():
    parser = argparse.ArgumentParser(description="Kali Linux Tools API Server")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port (default {API_PORT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    API_PORT = args.port
    logger.info(f"Starting Kali Linux Tools API Server on port {API_PORT}")
    app.run(host="0.0.0.0", port=API_PORT, debug=args.debug)
