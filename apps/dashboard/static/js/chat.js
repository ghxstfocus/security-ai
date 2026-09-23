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
