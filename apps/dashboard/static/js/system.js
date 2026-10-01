/* ------------------------------------------------------------------
 * system.js — Polling-Client fuer /api/system/state (Punkt 66).
 *
 * CSP-konform:
 * - Kein innerHTML, kein onclick, kein eval.
 * - addEventListener, createElement, textContent.
 * - fetch mit credentials: same-origin.
 * - connect-src 'self' deckt fetch ab.
 *
 * Polling: 30s. Puffer: 240 Werte (2h bei 30s).
 * Kein localStorage, kein sessionStorage.
 * Feste Skala 0..100 fuer CPU/RAM.
 * ------------------------------------------------------------------ */

"use strict";

(function () {
    var POLL_MS = 30000;
    var MAX_SAMPLES = 240;
    var cpuHistory = [];
    var ramHistory = [];

    function fetchState() {
        return fetch("/api/system/state", {
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

    function setText(id, value) {
        var el = document.getElementById(id);
        if (el) {
            el.textContent = String(value);
        }
    }

    function fmtPercent(v) {
        if (typeof v !== "number") {
            return "—";
        }
        return v.toFixed(1) + " %";
    }

    function fmtGb(v) {
        if (typeof v !== "number") {
            return "—";
        }
        return v.toFixed(1) + " GB";
    }

    function fmtUptime(sec) {
        if (typeof sec !== "number" || sec < 0) {
            return "—";
        }
        var d = Math.floor(sec / 86400);
        var h = Math.floor((sec % 86400) / 3600);
        var m = Math.floor((sec % 3600) / 60);
        return d + "d " + h + "h " + m + "m";
    }

    function renderSparkline(polyId, values) {
        var poly = document.getElementById(polyId);
        if (!poly || !Array.isArray(values) || values.length === 0) {
            return;
        }
        var w = 60;
        var h = 20;
        var n = values.length;
        var step = n > 1 ? w / (n - 1) : w;
        var pts = [];
        for (var i = 0; i < n; i++) {
            var x = (i * step).toFixed(2);
            var v = Math.max(0, Math.min(100, values[i]));
            var y = (h - (v / 100) * h).toFixed(2);
            pts.push(x + "," + y);
        }
        poly.setAttribute("points", pts.join(" "));
    }

    function renderServices(list) {
        var tbody = document.getElementById("system-services");
        if (!tbody || !Array.isArray(list)) {
            return;
        }
        clear(tbody);
        list.forEach(function (s) {
            var tr = document.createElement("tr");
            var tdU = document.createElement("td");
            tdU.textContent = String(s.unit || "—");
            var tdS = document.createElement("td");
            var span = document.createElement("span");
            var st = String(s.status || "unbekannt");
            if (st === "active") {
                span.className = "badge badge-cyan";
            } else if (st === "inactive" || st === "failed") {
                span.className = "badge badge-red";
            } else {
                span.className = "badge badge-yellow";
            }
            span.textContent = st;
            tdS.appendChild(span);
            tr.appendChild(tdU);
            tr.appendChild(tdS);
            tbody.appendChild(tr);
        });
    }

    function update(state) {
        if (!state || !state.system) {
            return;
        }
        var s = state.system;
        setText("system-cpu-value", fmtPercent(s.cpu_percent));
        setText("system-cpu-count",
                typeof s.cpu_count === "number" ? s.cpu_count : "—");
        setText("system-ram-value", fmtPercent(s.ram_percent));
        setText("system-ram-detail",
                fmtGb(s.ram_used_gb) + " / " + fmtGb(s.ram_total_gb));
        setText("system-disk-percent", fmtPercent(s.disk_root_percent));
        setText("system-disk-detail",
                fmtGb(s.disk_root_used_gb) + " / "
                + fmtGb(s.disk_root_total_gb));
        setText("system-load-1", s.loadavg_1 != null ? s.loadavg_1 : "—");
        setText("system-load-5", s.loadavg_5 != null ? s.loadavg_5 : "—");
        setText("system-load-15", s.loadavg_15 != null ? s.loadavg_15 : "—");
        setText("system-uptime", fmtUptime(s.uptime_seconds));
        setText("system-timestamp", state.timestamp || "—");

        if (typeof s.cpu_percent === "number") {
            cpuHistory.push(s.cpu_percent);
            if (cpuHistory.length > MAX_SAMPLES) { cpuHistory.shift(); }
            renderSparkline("system-cpu-line", cpuHistory);
        }
        if (typeof s.ram_percent === "number") {
            ramHistory.push(s.ram_percent);
            if (ramHistory.length > MAX_SAMPLES) { ramHistory.shift(); }
            renderSparkline("system-ram-line", ramHistory);
        }
        renderServices(s.services);
    }

    function tick() {
        fetchState().then(update);
    }

    function init() {
        tick();
        setInterval(tick, POLL_MS);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
