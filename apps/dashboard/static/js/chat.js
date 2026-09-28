/* ------------------------------------------------------------------
 * chat.js — Chat-Widget-Client.
 *
 * Auflage 95: robust bei fehlenden IDs (Guard am Anfang).
 * Auflage 96: kein Inline-JS, kein on*=, addEventListener.
 * Auflage 239: kein innerHTML mit Daten, textContent.
 * Auflage 241: nur console.debug.
 *
 * CSRF: Header X-CSRF-Token aus <body data-csrf-token>.
 * fetch-Ziel: /api/chat (JSON).
 * ------------------------------------------------------------------ */

"use strict";

(function () {
    function getToken() {
        return document.body.dataset.csrfToken || "";
    }

    function renderMessage(container, text, kind) {
        var div = document.createElement("div");
        div.className = "chat-msg chat-msg-" + kind;
        div.textContent = text;
        container.appendChild(div);
    }

    // Punkt 30 (A765-A767): Links als eigene Liste
    // unter der Antwort. Kein innerHTML, kein Regex.
    // Server liefert die Links fertig (label, href).
    function renderLinks(container, links) {
        if (!Array.isArray(links) || links.length === 0) {
            return;
        }
        var wrap = document.createElement("div");
        wrap.className = "chat-links";
        links.forEach(function (entry) {
            if (!entry || typeof entry.href !== "string") {
                return;
            }
            if (entry.href.charAt(0) !== "/") {
                return;
            }
            var a = document.createElement("a");
            a.href = entry.href;
            a.textContent = String(entry.label || entry.href);
            wrap.appendChild(a);
        });
        if (wrap.childNodes.length > 0) {
            container.appendChild(wrap);
        }
    }

    // Punkt 33 (A867/A868): Navigations-Hinweise.
    // Nach answer-Text und links. Kein innerHTML.
    function renderNavLinks(container, navLinks) {
        if (!Array.isArray(navLinks) || navLinks.length === 0) {
            return;
        }
        var wrap = document.createElement("div");
        wrap.className = "chat-nav-links";
        navLinks.forEach(function (entry) {
            if (!entry || typeof entry.href !== "string") {
                return;
            }
            if (entry.href.charAt(0) !== "/") {
                return;
            }
            var a = document.createElement("a");
            a.href = entry.href;
            a.textContent = String(entry.label || entry.href);
            wrap.appendChild(a);
        });
        if (wrap.childNodes.length > 0) {
            container.appendChild(wrap);
        }
    }

    function init() {
        var input = document.getElementById("chat-input");
        var send = document.getElementById("chat-send");
        var messages = document.getElementById("chat-messages");
        var deep = document.getElementById("chat-deep");
        // Auflage 95: Guard.
        if (!input || !send || !messages) {
            return;
        }

        function sendQuestion() {
            var q = input.value.trim();
            if (!q) {
                return;
            }
            renderMessage(messages, q, "user");
            input.value = "";
            var body = {question: q, detail: false};
            if (deep && deep.checked) {
                body.detail = true;
            }
            fetch("/api/chat", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": getToken(),
                },
                body: JSON.stringify(body),
            }).then(function (resp) {
                return resp.json().then(function (data) {
                    return {status: resp.status, data: data};
                }).catch(function () {
                    return {status: resp.status, data: null};
                });
            }).then(function (result) {
                if (result.status === 200 && result.data) {
                    renderMessage(
                        messages,
                        String(result.data.answer || ""),
                        "assistant",
                    );
                    renderLinks(messages, result.data.links);
                    renderNavLinks(messages, result.data.nav_links);
                    return;
                }
                var err = "Fehler";
                if (result.data && result.data.error) {
                    err = String(result.data.error);
                }
                renderMessage(messages, err, "error");
            }).catch(function () {
                renderMessage(messages, "Netzwerkfehler", "error");
            });
        }

        send.addEventListener("click", sendQuestion);
        input.addEventListener("keydown", function (ev) {
            if (ev.key === "Enter" && !ev.shiftKey) {
                ev.preventDefault();
                sendQuestion();
            }
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
