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

    function clearOutput(card) {
        var box = card.querySelector(".tool-output");
        if (!box) return null;
        while (box.firstChild) {
            box.removeChild(box.firstChild);
        }
        box.hidden = false;
        return box;
    }

    function showSpinner(card, on) {
        var sp = card.querySelector(".tool-spinner");
        if (!sp) return;
        sp.hidden = !on;
    }

    function appendLine(parent, text, cls) {
        var line = document.createElement("div");
        if (cls) line.className = cls;
        line.textContent = text;
        parent.appendChild(line);
    }

    function appendKeyValue(parent, key, value) {
        var line = document.createElement("div");
        line.className = "tool-kv";
        var k = document.createElement("span");
        k.className = "tool-kv-key";
        k.textContent = key + ": ";
        var v = document.createElement("span");
        v.className = "tool-kv-value";
        v.textContent = (value === null || value === undefined)
            ? "-" : String(value);
        line.appendChild(k);
        line.appendChild(v);
        parent.appendChild(line);
    }

    function renderValue(parent, value) {
        if (value === null || value === undefined) {
            appendLine(parent, "-");
            return;
        }
        if (typeof value === "string") {
            if (value.indexOf("\n") !== -1) {
                var pre = document.createElement("pre");
                pre.className = "tool-pre";
                pre.textContent = value;
                parent.appendChild(pre);
            } else {
                appendLine(parent, value);
            }
            return;
        }
        if (Array.isArray(value)) {
            if (value.length === 0) {
                appendLine(parent, "(keine Eintraege)");
                return;
            }
            for (var i = 0; i < value.length; i++) {
                var item = value[i];
                if (item !== null && typeof item === "object") {
                    var inner = document.createElement("div");
                    inner.className = "tool-item";
                    var keys = Object.keys(item);
                    for (var j = 0; j < keys.length; j++) {
                        appendKeyValue(inner, keys[j], item[keys[j]]);
                    }
                    parent.appendChild(inner);
                } else {
                    appendLine(parent, String(item));
                }
            }
            return;
        }
        if (typeof value === "object") {
            var keys2 = Object.keys(value);
            if (keys2.length === 0) {
                appendLine(parent, "(keine Daten)");
                return;
            }
            for (var k = 0; k < keys2.length; k++) {
                var v = value[keys2[k]];
                if (v !== null && typeof v === "object") {
                    appendLine(parent, keys2[k] + ":");
                    var sub = document.createElement("div");
                    sub.className = "tool-sub";
                    renderValue(sub, v);
                    parent.appendChild(sub);
                } else {
                    appendKeyValue(parent, keys2[k], v);
                }
            }
            return;
        }
        appendLine(parent, String(value));
    }

    function showError(card, message) {
        var box = clearOutput(card);
        if (!box) return;
        var err = document.createElement("div");
        err.className = "tool-error";
        err.textContent = message;
        box.appendChild(err);
    }

    function showSuccess(card, output) {
        var box = clearOutput(card);
        if (!box) return;
        renderValue(box, output);
    }

    function handleSubmit(event) {
        event.preventDefault();
        var form = event.target;
        var card = form.closest(".tool-card");
        if (!card) return;
        var toolName = form.getAttribute("data-tool") || "";
        var args = buildArgs(form);
        var token = getCsrfToken();
        showSpinner(card, true);
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
                showError(
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
                showSuccess(card, data.output);
            } else {
                showError(
                    card,
                    data.error || "Werkzeug nicht ausgefuehrt."
                );
            }
        }).catch(function () {
            showError(card, "Netzwerkfehler.");
        }).finally(function () {
            showSpinner(card, false);
        });
    }

    var forms = document.querySelectorAll(".tool-form");
    for (var i = 0; i < forms.length; i++) {
        forms[i].addEventListener("submit", handleSubmit);
    }
})();
