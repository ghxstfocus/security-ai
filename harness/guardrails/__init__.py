"""
harness/guardrails — Nicht-ueberschreibbare Schutzmechanismen.

Code, nicht Prompt. Koennen nicht durch das Modell
deaktiviert werden. Fail closed: wenn ein Guardrail nicht
pruefen kann, blockiert er.

Geplante Module (siehe docs/ARCHITECTURE.md 3.8):
  scope_guard, self_mod_guard, audit_guard,
  prompt_injection_guard.

Teilweise abgedeckt in harness/policy_engine (globale
Pruefer target_in_scope, authorized_target, no_shell_chars,
no_path_traversal, no_null_bytes).

Geplant fuer Phase 4.
"""
