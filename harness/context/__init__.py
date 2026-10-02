# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
harness/context — Kontext-Bauer fuer lokales LLM.

Baut vor jedem LLM-Aufruf einen strukturierten Kontext
aus Events, DB-Historie, Log-Ausschnitten und Inventory-
Status. Filtert Rohdaten (Prompt-Injection-Schutz).
Selbst auditierbar.

Geplant fuer Phase 3.5 (Lokale KI-Schicht).
"""
