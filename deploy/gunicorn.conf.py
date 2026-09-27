"""gunicorn-Konfiguration (Punkt 16, Auflage 653).

Bindet auf 127.0.0.1:5000. nginx proxyt auf 443.
Logs gehen nach stdout/stderr -> journal.
"""

bind = "127.0.0.1:5000"
workers = 2
threads = 2
timeout = 180
accesslog = "-"
errorlog = "-"
loglevel = "info"
proc_name = "security-ai-dashboard"

# Punkt 16b: Control-Socket deaktivieren. systemd
# ProtectSystem=strict macht das Projektverzeichnis
# read-only; gunicorn versucht sonst, .gunicorn/ dort
# anzulegen (ERROR im Journal). Der Control-Socket ist
# optional und wird hier nicht gebraucht.
control_socket_disable = True
