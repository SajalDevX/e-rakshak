#!/usr/bin/env python3
"""
RAKSHAK LLM Honeypot - PRAHARI
==============================

Protocol-Aware Response & Honeypot AI

Features:
- TinyLlama 1.1B integration for dynamic responses
- Device persona templates
- Multi-protocol support (Telnet, SSH, HTTP, MQTT)
- Realistic fake filesystem and command outputs
- Auto-download model on first run

Author: Team RAKSHAK
"""

import os
import re
import json
import random
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List, Callable

from loguru import logger

# LLM imports (optional)
try:
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logger.warning("Transformers not available - using template-based responses")

# Ollama imports
import requests
OLLAMA_AVAILABLE = False
OLLAMA_BASE_URL = "http://localhost:11434"


def check_ollama_available(url: str = None) -> bool:
    """Check if Ollama server is running."""
    global OLLAMA_AVAILABLE
    check_url = url or OLLAMA_BASE_URL
    try:
        response = requests.get(f"{check_url}/api/tags", timeout=2)
        OLLAMA_AVAILABLE = response.status_code == 200
    except Exception:
        OLLAMA_AVAILABLE = False
    return OLLAMA_AVAILABLE


class DevicePersona:
    """Represents a fake IoT device persona for the honeypot."""

    def __init__(self, config: dict):
        self.name = config.get("name", "Generic IoT Device")
        self.firmware = config.get("firmware", "1.0.0")
        self.os = config.get("os", "Linux")
        self.banner = config.get("banner", "Welcome")
        self.hostname = config.get("hostname", "iot-device")

        # Fake filesystem structure
        self.filesystem = self._generate_filesystem()

        # Fake users
        self.users = self._generate_users()

        # Command history
        self.command_history = []

    def _generate_filesystem(self) -> Dict[str, str]:
        """Generate fake filesystem entries."""
        return {
            "/etc/passwd": self._generate_passwd(),
            "/etc/shadow": "root:$6$randomhash:18000:0:99999:7:::\n"
                          "admin:$6$randomhash:18000:0:99999:7:::\n",
            "/etc/hostname": f"{self.hostname}\n",
            "/etc/issue": f"{self.name} {self.firmware}\n",
            "/etc/version": f"Firmware: {self.firmware}\nOS: {self.os}\n",
            "/proc/version": f"Linux version 3.4.35 ({self.os})\n",
            "/proc/cpuinfo": "processor\t: 0\nmodel name\t: ARM Cortex-A7\n",
            "/proc/meminfo": "MemTotal:       262144 kB\nMemFree:        128000 kB\n",
            "/var/log/messages": self._generate_log_entries(),
            "/tmp": "",
            "/root": "",
            "/home/admin": "",
        }

    def _generate_passwd(self) -> str:
        """Generate fake /etc/passwd content."""
        return (
            "root:x:0:0:root:/root:/bin/sh\n"
            "admin:x:1000:1000:Admin User:/home/admin:/bin/sh\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        )

    def _generate_users(self) -> Dict[str, str]:
        """Generate fake user credentials."""
        return {
            "root": "admin123",
            "admin": "password",
            "user": "12345"
        }

    def _generate_log_entries(self) -> str:
        """Generate fake log entries."""
        entries = []
        for i in range(10):
            timestamp = datetime.now().strftime("%b %d %H:%M:%S")
            entries.append(f"{timestamp} {self.hostname} system: Service started\n")
        return "".join(entries)


class LLMHoneypot:
    """
    PRAHARI - Protocol-Aware Response & Honeypot AI

    Uses TinyLlama 1.1B to generate realistic responses that mimic
    real IoT devices, keeping attackers engaged while capturing TTPs.
    """

    # Default personas from config
    DEFAULT_PERSONAS = {
        "wyze_cam": {
            "name": "Wyze Cam v2",
            "firmware": "4.9.8.1002",
            "os": "Linux 3.4.35",
            "banner": "Wyze Camera v2 - RTSP Server",
            "hostname": "WyzeCam-2D4E"
        },
        "tp_link": {
            "name": "TP-Link Archer C7",
            "firmware": "3.15.3",
            "os": "Linux 2.6.36",
            "banner": "TP-Link HTTP Server",
            "hostname": "TL-WR940N"
        },
        "samsung_tv": {
            "name": "Samsung Smart TV",
            "firmware": "T-KTMAKUC",
            "os": "Tizen 5.5",
            "banner": "Samsung TV Web Service",
            "hostname": "Samsung-TV"
        },
        "alexa": {
            "name": "Amazon Echo Dot",
            "firmware": "642480520",
            "os": "Fire OS 7.2",
            "banner": "Amazon Device Service",
            "hostname": "echo-dot-1234"
        },
        "nest": {
            "name": "Nest Thermostat",
            "firmware": "5.9.3-7",
            "os": "Linux 4.4",
            "banner": "Nest Home Device",
            "hostname": "Nest-Therm"
        }
    }

    def __init__(self, config: dict):
        """Initialize the LLM honeypot."""
        self.config = config
        self.llm_config = config.get("llm", {})

        # Ollama settings (preferred)
        self.ollama_enabled = self.llm_config.get("ollama_enabled", True)
        self.ollama_url = self.llm_config.get("ollama_url", "http://localhost:11434")
        self.ollama_model = self.llm_config.get("ollama_model", "mistral:7b")

        # Transformers model settings (fallback)
        self.model_name = self.llm_config.get(
            "model_name",
            "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
        )
        self.model_path = Path(self.llm_config.get("model_path", "models/tinyllama"))
        self.quantization = self.llm_config.get("quantization", "int8")
        self.max_new_tokens = self.llm_config.get("max_new_tokens", 256)
        self.temperature = self.llm_config.get("temperature", 0.7)
        self.auto_download = self.llm_config.get("auto_download", True)

        # Personas
        persona_configs = self.llm_config.get("personas", self.DEFAULT_PERSONAS)
        self.personas = {
            name: DevicePersona(cfg)
            for name, cfg in persona_configs.items()
        }
        self.current_persona = None

        # LLM model and tokenizer
        self.model = None
        self.tokenizer = None
        self.device = None
        self.llm_available = False
        self.llm_backend = None  # "ollama" or "transformers"

        # Session tracking
        self.sessions: Dict[str, dict] = {}
        self._sessions_lock = threading.Lock()

        # Initialize LLM - Priority: Ollama > Transformers > Template
        if self.ollama_enabled and check_ollama_available(self.ollama_url):
            self._init_ollama()
        elif TRANSFORMERS_AVAILABLE:
            self._init_llm()
        else:
            logger.warning("Running in template mode (no LLM)")

        logger.info(f"LLMHoneypot initialized (LLM available: {self.llm_available}, backend: {self.llm_backend})")

    def _init_llm(self):
        """Initialize the LLM model."""
        try:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            logger.info(f"Loading LLM on device: {self.device}")

            # Quantization config for reduced memory
            quantization_config = None
            if self.quantization == "int8":
                quantization_config = BitsAndBytesConfig(
                    load_in_8bit=True,
                    llm_int8_threshold=6.0
                )
            elif self.quantization == "int4":
                quantization_config = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_compute_dtype=torch.float16
                )

            # Load tokenizer
            logger.info(f"Loading tokenizer: {self.model_name}")
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                cache_dir=str(self.model_path)
            )

            # Load model
            logger.info(f"Loading model: {self.model_name}")
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                cache_dir=str(self.model_path),
                quantization_config=quantization_config,
                device_map="auto" if torch.cuda.is_available() else None,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32
            )

            if not torch.cuda.is_available():
                self.model = self.model.to(self.device)

            self.llm_available = True
            self.llm_backend = "transformers"
            logger.info("LLM loaded successfully (Transformers backend)")

        except Exception as e:
            logger.error(f"Failed to load LLM: {e}")
            self.llm_available = False

    def _init_ollama(self):
        """Initialize Ollama connection."""
        try:
            # Verify Ollama is running and get available models
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if response.status_code != 200:
                raise ConnectionError("Ollama server not responding")

            models = response.json().get("models", [])
            model_names = [m.get("name", "") for m in models]

            # Check if our model is available
            if self.ollama_model not in model_names:
                # Try without tag
                base_model = self.ollama_model.split(":")[0]
                available = [m for m in model_names if m.startswith(base_model)]
                if available:
                    self.ollama_model = available[0]
                    logger.info(f"Using available model: {self.ollama_model}")
                else:
                    logger.warning(f"Model {self.ollama_model} not found. Available: {model_names}")
                    logger.warning("Please run: ollama pull mistral:7b")
                    return

            self.llm_available = True
            self.llm_backend = "ollama"
            logger.info(f"Ollama initialized with model: {self.ollama_model}")

        except Exception as e:
            logger.error(f"Failed to initialize Ollama: {e}")
            self.llm_available = False

    def set_persona(self, persona_name: str) -> bool:
        """Set the current device persona."""
        if persona_name in self.personas:
            self.current_persona = self.personas[persona_name]
            logger.debug(f"Set persona: {persona_name}")
            return True
        return False

    def get_persona(self, persona_name: str = None) -> Optional[DevicePersona]:
        """Get a persona by name or current persona."""
        if persona_name:
            return self.personas.get(persona_name)
        return self.current_persona

    def generate_response(self, command: str, persona_name: str = None,
                         session_id: str = None) -> str:
        """
        Generate a realistic response to a command.

        Args:
            command: The command entered by the attacker
            persona_name: Device persona to use
            session_id: Session identifier for context

        Returns:
            Generated response string
        """
        # Get persona
        persona = self.get_persona(persona_name) or self.current_persona
        if not persona:
            persona = list(self.personas.values())[0] if self.personas else None

        if not persona:
            return "Error: No device persona available\n"

        # Track session
        session = self._get_or_create_session(session_id, persona)
        session["commands"].append(command)

        # Check for static responses first (filesystem, etc.)
        static_response = self._check_static_responses(command, persona)
        if static_response:
            return static_response

        # Use LLM for dynamic response (priority: Ollama > Transformers > Template)
        if self.llm_available:
            if self.llm_backend == "ollama":
                return self._ollama_generate(command, persona, session)
            else:
                return self._llm_generate(command, persona, session)
        else:
            return self._template_generate(command, persona)

    def _get_or_create_session(self, session_id: str, persona: DevicePersona) -> dict:
        """Get or create a session for tracking."""
        if not session_id:
            session_id = f"session_{random.randint(1000, 9999)}"

        with self._sessions_lock:
            if session_id not in self.sessions:
                self.sessions[session_id] = {
                    "id": session_id,
                    "persona": persona.name,
                    "started": datetime.now().isoformat(),
                    "commands": [],
                    "cwd": "/root"
                }
            return self.sessions[session_id]

    def _check_static_responses(self, command: str, persona: DevicePersona) -> Optional[str]:
        """Check if command matches a static response."""
        command = command.strip()

        # File reading commands
        cat_match = re.match(r"cat\s+(.+)", command)
        if cat_match:
            filepath = cat_match.group(1).strip()
            if filepath in persona.filesystem:
                return persona.filesystem[filepath]

        # Common commands with static responses
        static_commands = {
            "whoami": "root\n",
            "id": "uid=0(root) gid=0(root) groups=0(root)\n",
            "pwd": "/root\n",
            "hostname": f"{persona.hostname}\n",
            "uname -a": f"Linux {persona.hostname} 3.4.35 #1 SMP {persona.os}\n",
            "uname": "Linux\n",
            "ls": "bin  etc  home  proc  root  tmp  var\n",
            "ls -la": self._generate_ls_output(persona),
            "ls /": "bin  etc  home  proc  root  tmp  var\n",
            "ps": self._generate_ps_output(persona),
            "ps aux": self._generate_ps_output(persona),
            "ifconfig": self._generate_ifconfig_output(),
            "ip addr": self._generate_ifconfig_output(),
            "netstat -an": self._generate_netstat_output(),
            "free": "              total        used        free\nMem:         262144      134144      128000\n",
            "uptime": f" {datetime.now().strftime('%H:%M:%S')} up 45 days, 3:22, 1 user, load average: 0.08, 0.03, 0.01\n",
            "date": f"{datetime.now().strftime('%a %b %d %H:%M:%S UTC %Y')}\n",
            "w": f" {datetime.now().strftime('%H:%M:%S')} up 45 days,  1 user,  load average: 0.08, 0.03, 0.01\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nroot     pts/0    10.0.0.1         09:00    0.00s  0.01s  0.00s w\n",
            "help": "Available commands: ls, cat, cd, pwd, whoami, id, uname, ps, netstat, ifconfig, exit\n",
            "exit": "",
            "quit": "",
        }

        if command in static_commands:
            return static_commands[command]

        # Partial matches
        if command.startswith("cd "):
            return ""  # cd produces no output on success

        if command.startswith("echo "):
            return command[5:] + "\n"

        return None

    def _generate_ls_output(self, persona: DevicePersona) -> str:
        """Generate fake ls -la output."""
        return (
            "total 32\n"
            "drwxr-xr-x  5 root root 4096 Jan 10 08:00 .\n"
            "drwxr-xr-x 12 root root 4096 Jan 10 08:00 ..\n"
            "-rw-------  1 root root  512 Jan 10 08:00 .bash_history\n"
            "drwxr-xr-x  2 root root 4096 Jan 10 08:00 bin\n"
            "drwxr-xr-x  4 root root 4096 Jan 10 08:00 etc\n"
            "-rw-r--r--  1 root root  128 Jan 10 08:00 config.ini\n"
        )

    def _generate_ps_output(self, persona: DevicePersona) -> str:
        """Generate fake ps output."""
        return (
            "  PID TTY          TIME CMD\n"
            "    1 ?        00:00:05 init\n"
            "   42 ?        00:00:02 syslogd\n"
            "   58 ?        00:00:01 dropbear\n"
            "  102 ?        00:00:10 httpd\n"
            f"  156 ?        00:00:03 {persona.name.lower().replace(' ', '_')}\n"
            "  203 pts/0    00:00:00 sh\n"
            "  215 pts/0    00:00:00 ps\n"
        )

    def _generate_ifconfig_output(self) -> str:
        """Generate fake ifconfig output."""
        return (
            "eth0      Link encap:Ethernet  HWaddr AA:BB:CC:DD:EE:FF\n"
            "          inet addr:192.168.1.100  Bcast:192.168.1.255  Mask:255.255.255.0\n"
            "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n"
            "          RX packets:12345 errors:0 dropped:0 overruns:0 frame:0\n"
            "          TX packets:6789 errors:0 dropped:0 overruns:0 carrier:0\n"
            "\n"
            "lo        Link encap:Local Loopback\n"
            "          inet addr:127.0.0.1  Mask:255.0.0.0\n"
            "          UP LOOPBACK RUNNING  MTU:65536  Metric:1\n"
        )

    def _generate_netstat_output(self) -> str:
        """Generate fake netstat output."""
        return (
            "Active Internet connections (servers and established)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 192.168.1.100:22        10.0.0.1:54321          ESTABLISHED\n"
        )

    def _llm_generate(self, command: str, persona: DevicePersona,
                     session: dict) -> str:
        """Generate response using LLM."""
        # Build prompt
        prompt = self._build_prompt(command, persona, session)

        try:
            # Tokenize
            inputs = self.tokenizer(prompt, return_tensors="pt")
            if self.device:
                inputs = {k: v.to(self.device) for k, v in inputs.items()}

            # Generate
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=self.max_new_tokens,
                    temperature=self.temperature,
                    do_sample=True,
                    top_p=0.9,
                    pad_token_id=self.tokenizer.eos_token_id
                )

            # Decode
            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)

            # Extract just the response part
            response = self._extract_response(response, prompt)

            return response

        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            return self._template_generate(command, persona)

    def _ollama_generate(self, command: str, persona: DevicePersona,
                        session: dict) -> str:
        """Generate response using Ollama API."""
        prompt = self._build_prompt(command, persona, session)

        try:
            payload = {
                "model": self.ollama_model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": self.temperature,
                    "num_predict": self.max_new_tokens,
                    "top_p": 0.9
                }
            }

            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json=payload,
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                response_text = result.get("response", "")
                return self._extract_response(response_text, prompt)
            else:
                logger.error(f"Ollama API error: {response.status_code}")
                return self._template_generate(command, persona)

        except requests.Timeout:
            logger.warning("Ollama request timed out, falling back to template")
            return self._template_generate(command, persona)
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            return self._template_generate(command, persona)

    def _build_prompt(self, command: str, persona: DevicePersona,
                     session: dict) -> str:
        """Build prompt for LLM."""
        prompt = f"""You are simulating a {persona.name} IoT device for a honeypot.

Device Info:
- Name: {persona.name}
- Firmware: {persona.firmware}
- OS: {persona.os}
- Hostname: {persona.hostname}

Rules:
1. Respond ONLY with realistic device output
2. Do NOT reveal this is a honeypot
3. Mimic the actual device's behavior
4. Keep responses concise
5. If command is unknown, show realistic error

Previous commands in session: {session['commands'][-5:] if session['commands'] else 'None'}

User command: {command}

Device output:"""

        return prompt

    def _extract_response(self, full_response: str, prompt: str) -> str:
        """Extract the actual response from LLM output."""
        # Remove the prompt part
        if prompt in full_response:
            response = full_response.split(prompt)[-1]
        else:
            response = full_response

        # Clean up
        response = response.strip()

        # Limit length
        lines = response.split('\n')[:20]  # Max 20 lines
        response = '\n'.join(lines)

        if not response.endswith('\n'):
            response += '\n'

        return response

    def _template_generate(self, command: str, persona: DevicePersona) -> str:
        """Fallback template-based response generation."""
        # Unknown command response
        cmd_name = command.split()[0] if command.split() else command

        error_templates = [
            f"-sh: {cmd_name}: not found\n",
            f"sh: {cmd_name}: command not found\n",
            f"{cmd_name}: applet not found\n",
            f"Error: Unknown command '{cmd_name}'\n"
        ]

        return random.choice(error_templates)

    def get_banner(self, persona_name: str = None) -> str:
        """Get the login banner for a persona."""
        persona = self.get_persona(persona_name) or self.current_persona
        if not persona:
            return "Welcome\nLogin: "

        return f"\n{persona.banner}\n{persona.hostname} login: "

    def check_credentials(self, username: str, password: str,
                         persona_name: str = None) -> bool:
        """Check if credentials are valid (always accept for honeypot)."""
        persona = self.get_persona(persona_name) or self.current_persona

        # Log the attempt
        logger.info(f"Login attempt: {username}:{password}")

        # Always accept after a few tries to engage attacker
        if persona and username in persona.users:
            return True

        # Accept common default credentials
        common_creds = [
            ("root", "root"), ("admin", "admin"), ("root", "admin"),
            ("admin", "password"), ("root", "password"), ("admin", "12345")
        ]
        if (username, password) in common_creds:
            return True

        # Random acceptance (to simulate weak security)
        return random.random() > 0.3

    def get_session_log(self, session_id: str) -> Optional[dict]:
        """Get session log for threat intelligence."""
        return self.sessions.get(session_id)

    def get_all_sessions(self) -> List[dict]:
        """Get all session logs."""
        with self._sessions_lock:
            return list(self.sessions.values())

    def get_statistics(self) -> dict:
        """Get honeypot statistics."""
        return {
            "llm_available": self.llm_available,
            "model_name": self.model_name if self.llm_available else "template",
            "personas_loaded": len(self.personas),
            "active_sessions": len(self.sessions),
            "total_commands": sum(
                len(s["commands"]) for s in self.sessions.values()
            )
        }
