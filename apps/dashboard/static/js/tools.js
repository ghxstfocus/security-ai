"use strict";
(function () {
    function getCsrfToken() {
        var body = document.body;
        return body ? body.getAttribute("data-csrf-token") : "";
    }

    function buildArgs(form) {
        var inputs = form.querySelectorAll("input[name]");
        var args = {};
        for (var i = 0; i < inputs.length; i++) {
            var el = inputs[i];
            var val = el.value;
            if (val !== "") {
                args[el.name] = val;
            }
        }
        return args;
    }

    function showOutput(card, text) {
        var pre = card.querySelector(".tool-output");
        if (!pre) return;
        pre.textContent = text;
        pre.hidden = false;
    }

    function handleSubmit(event) {
        event.preventDefault();
        var form = event.target;
        var card = form.closest(".tool-card");
        if (!card) return;
        var toolName = form.getAttribute("data-tool") || "";
        var args = buildArgs(form);
        var token = getCsrfToken();
        fetch("/api/tools/run", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": token,
            },
            body: JSON.stringify({tool: toolName, args: args}),
        }).then(function (resp) {
            if (resp.status === 429) {
                var retry = resp.headers.get("Retry-After") || "?";
                showOutput(
                    card,
                    "Zu viele Anfragen. Bitte "
                        + retry + " Sekunden warten."
                );
                return null;
            }
            return resp.json().catch(function () { return null; });
        }).then(function (data) {
            if (!data) return;
            if (data.ok) {
                showOutput(card, JSON.stringify(data.output, null, 2));
            } else {
                showOutput(
                    card,
                    "Werkzeug nicht ausgefuehrt: "
                        + (data.error || "unbekannter Fehler")
                );
            }
        }).catch(function () {
            showOutput(card, "Netzwerkfehler.");
        });
    }

    var forms = document.querySelectorAll(".tool-form");
    for (var i = 0; i < forms.length; i++) {
        forms[i].addEventListener("submit", handleSubmit);
    }
})();
