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
    var cpuHistory = [];
    var ramHistory = [];

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

    function netBadgeClass(net) {
        if (net === "Gastnetz") { return "badge badge-yellow"; }
        if (net === "Extern") { return "badge badge-red"; }
        return "badge badge-cyan";
    }

    function renderDeviceRow(container, dev) {
        var tr = document.createElement("tr");
        tr.className = "live-device";

        var tdName = document.createElement("td");
        var aName = document.createElement("a");
        aName.className = "live-device-link";
        aName.href = "/inventory/" + encodeURIComponent(
            String(dev.identifier || "")
        );
        aName.textContent = String(
            dev.entity_name || "—"
        );
        tdName.appendChild(aName);

        var tdIp = document.createElement("td");
        tdIp.className = "live-device-ip";
        tdIp.textContent = String(dev.last_ip || "—");

        var tdNet = document.createElement("td");
        var netSpan = document.createElement("span");
        netSpan.className = netBadgeClass(
            String(dev.network_type || "")
        );
        netSpan.textContent = String(dev.network_type || "—");
        tdNet.appendChild(netSpan);

        tr.appendChild(tdName);
        tr.appendChild(tdIp);
        tr.appendChild(tdNet);
        container.appendChild(tr);
    }

    function alertBadgeClass(cat) {
        if (cat === "CONFIRMED" || cat === "SECURITY_ALERT") {
            return "badge badge-red";
        }
        if (cat === "SUSPICION") { return "badge badge-yellow"; }
        return "badge badge-cyan";
    }

    function renderAlertRow(container, entry) {
        var tr = document.createElement("tr");
        tr.className = "live-alert";

        var tdTs = document.createElement("td");
        tdTs.className = "live-alert-ts";
        if (entry.can_link && entry.audit_id) {
            var aTs = document.createElement("a");
            aTs.className = "live-alert-link";
            aTs.href = "/audit/" + encodeURIComponent(
                String(entry.audit_id)
            );
            aTs.textContent = String(entry.timestamp || "—");
            tdTs.appendChild(aTs);
        } else {
            tdTs.textContent = String(entry.timestamp || "—");
        }

        var tdCat = document.createElement("td");
        var catSpan = document.createElement("span");
        catSpan.className = alertBadgeClass(
            String(entry.category || "")
        );
        catSpan.textContent = String(entry.category || "—");
        tdCat.appendChild(catSpan);

        var tdRule = document.createElement("td");
        tdRule.className = "live-alert-rule";
        tdRule.textContent = String(entry.rule_id || "—");

        tr.appendChild(tdTs);
        tr.appendChild(tdCat);
        tr.appendChild(tdRule);
        container.appendChild(tr);
    }

    function renderSparkline(svgEl, polyEl, values) {
        if (!svgEl || !polyEl || !Array.isArray(values)
                || values.length === 0) {
            return;
        }
        var w = 60;
        var h = 20;
        var max = Math.max.apply(null, values);
        var min = Math.min.apply(null, values);
        var span = (max - min) || 1;
        var n = values.length;
        var step = n > 1 ? w / (n - 1) : w;
        var pts = [];
        for (var i = 0; i < n; i++) {
            var x = (i * step).toFixed(2);
            var y = (h - ((values[i] - min) / span) * h).toFixed(2);
            pts.push(x + "," + y);
        }
        polyEl.setAttribute("points", pts.join(" "));
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
        if (state.system) {
            var cpuVal = document.getElementById("sparkline-cpu-value");
            if (cpuVal && typeof state.system.cpu_percent === "number") {
                cpuVal.textContent = (
                    state.system.cpu_percent.toFixed(1) + " %"
                );
            }
            var ramVal = document.getElementById("sparkline-ram-value");
            if (ramVal && typeof state.system.ram_percent === "number") {
                ramVal.textContent = (
                    state.system.ram_percent.toFixed(1) + " % / "
                    + state.system.ram_used_gb + " GB"
                );
            }
            cpuHistory.push(state.system.cpu_percent || 0);
            ramHistory.push(state.system.ram_percent || 0);
            if (cpuHistory.length > 20) { cpuHistory.shift(); }
            if (ramHistory.length > 20) { ramHistory.shift(); }
            var cpuSvg = document.getElementById("sparkline-cpu");
            var cpuPoly = cpuSvg
                ? cpuSvg.querySelector("polyline") : null;
            renderSparkline(cpuSvg, cpuPoly, cpuHistory);
            var ramSvg = document.getElementById("sparkline-ram");
            var ramPoly = ramSvg
                ? ramSvg.querySelector("polyline") : null;
            renderSparkline(ramSvg, ramPoly, ramHistory);
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
