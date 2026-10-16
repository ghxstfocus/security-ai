// Copyright (C) 2026 Alexander Nohl
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Guardrails-Seite: Aktivieren/Deaktivieren per POST
// an /api/guardrails/<id>/state.
//
// CSP-konform: kein Inline-Script, kein onclick=,
// kein innerHTML mit Daten. CSRF-Token aus
// <body data-csrf-token="...">.

(function () {
  "use strict";

  function getCsrfToken() {
    return document.body.getAttribute("data-csrf-token") || "";
  }

  function setStatus(button, text) {
    var cell = button.parentElement;
    if (!cell) {
      return;
    }
    var status = cell.querySelector(".guardrail-status");
    if (!status) {
      status = document.createElement("span");
      status.className = "guardrail-status";
      cell.appendChild(status);
    }
    status.textContent = text;
  }

  function updateButton(button, newState) {
    if (newState === "enabled") {
      button.setAttribute("data-action", "disabled");
      button.textContent = "Deaktivieren";
    } else {
      button.setAttribute("data-action", "enabled");
      button.textContent = "Aktivieren";
    }
  }

  function handleClick(event) {
    var button = event.currentTarget;
    var guardrailId = button.getAttribute("data-guardrail-id");
    var action = button.getAttribute("data-action");
    if (!guardrailId || !action) {
      return;
    }

    button.disabled = true;
    setStatus(button, "Speichere...");

    fetch(
      "/api/guardrails/" + encodeURIComponent(guardrailId) + "/state",
      {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": getCsrfToken(),
        },
        body: JSON.stringify({ state: action }),
      }
    )
      .then(function (response) {
        return response.json().then(function (data) {
          return { ok: response.ok, data: data };
        });
      })
      .then(function (result) {
        if (result.ok && result.data && result.data.ok) {
          updateButton(button, action);
          setStatus(button, "Gespeichert.");
        } else {
          var msg =
            (result.data && result.data.error) || "Fehler";
          setStatus(button, msg);
        }
      })
      .catch(function () {
        setStatus(button, "Netzwerkfehler");
      })
      .finally(function () {
        button.disabled = false;
      });
  }

  function init() {
    var buttons = document.querySelectorAll(
      "button[data-guardrail-id]"
    );
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener("click", handleClick);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();