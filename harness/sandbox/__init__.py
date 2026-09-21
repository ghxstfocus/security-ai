"""
harness/sandbox — Sandbox-Profile fuer Tools.

Isolation pro Tool. Subprozess mit harten Limits (Zeit,
RAM, CPU, Netzwerk). Jedes Tool hat ein Sandbox-Profil.

Profile liegen in harness/sandbox/profiles/<name>.yaml.
Die erlaubten Namen stehen in
harness/tool_registry/tool.py::KNOWN_SANDBOX_PROFILES.

Aktueller Stand: tool.py prueft gegen KNOWN_SANDBOX_PROFILES.
Die tatsaechliche Ausfuehrung (Timeout, kein Shell,
Argument-Whitelist) liegt aktuell pro Tool, z. B. in
tools/nmap_scan.py.

Zentralisierung spaeter.
"""
