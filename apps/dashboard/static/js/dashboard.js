/* ------------------------------------------------------------------
 * dashboard.js — Polling-Client fuer /api/dashboard/state.
 *
 * T1+T5 (Punkt 55, Auflage 1699).
 *
 * CSP-konform:
 * - Kein innerHTML, kein onclick, kein eval.
 * - addEventListener, createElement, textContent.
 * - fetch mit credentials: same-origin.
 * - connect-src 'self' deckt fetch ab.
 *
 * Polling: 5s (Geraete, Alarme), 30s (Changes,
 * Zaehler). Zwei Timer.
 *
 * Fehler: stiller Retry, kein alert().
 * Kein localStorage, kein sessionStorage.
 * ------------------------------------------------------------------ */

"use strict";

(function () {
    var FAST_MS = 5000;
    var SLOW_MS = 30000;

    function fetchState() {
        return fetch("/api/dashboard/state", {
            credentials: "same-origin",
            headers: { "Accept": "application/json" },
        }).then(function (r) {
            if (!r.ok) {
                return null;
            }
            return r.json();
        }).catch(function () {
            return null;
        });
    }

    function clear(node) {
        while (node.firstChild) {
            node.removeChild(node.firstChild);
        }
    }

    function renderDeviceRow(container, dev) {
        var li = document.createElement("li");
        li.className = "live-device";
        var nameSpan = document.createElement("span");
        nameSpan.className = "live-device-name";
        nameSpan.textContent = String(
            dev.entity_name || dev.identifier || "?"
        );
        var netSpan = document.createElement("span");
        netSpan.className = "live-device-net";
        netSpan.textContent = String(dev.network_type || "");
        li.appendChild(nameSpan);
        li.appendChild(netSpan);
        container.appendChild(li);
    }

    function renderAlertRow(container, entry) {
        var li = document.createElement("li");
        li.className = "live-alert";
        var tsSpan = document.createElement("span");
        tsSpan.className = "live-alert-ts";
        tsSpan.textContent = String(entry.timestamp || "");
        var catSpan = document.createElement("span");
        catSpan.className = "live-alert-cat";
        catSpan.textContent = String(entry.category || "");
        li.appendChild(tsSpan);
        li.appendChild(catSpan);
        container.appendChild(li);
    }

    function updateFast(state) {
        if (!state) {
            return;
        }
        var devList = document.getElementById("live-devices");
        if (devList && state.devices) {
            clear(devList);
            var active = state.devices.active || [];
            active.forEach(function (d) {
                renderDeviceRow(devList, d);
            });
        }
        var alertList = document.getElementById("live-alerts");
        if (alertList && state.alerts) {
            clear(alertList);
            state.alerts.forEach(function (a) {
                renderAlertRow(alertList, a);
            });
        }
    }

    function updateSlow(state) {
        if (!state) {
            return;
        }
        var ts = document.getElementById("live-timestamp");
        if (ts && state.timestamp) {
            ts.textContent = String(state.timestamp);
        }
    }

    function tick(fn) {
        fetchState().then(fn);
    }

    function init() {
        tick(updateFast);
        tick(updateSlow);
        setInterval(function () { tick(updateFast); }, FAST_MS);
        setInterval(function () { tick(updateSlow); }, SLOW_MS);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
