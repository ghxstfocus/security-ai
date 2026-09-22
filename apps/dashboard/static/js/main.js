/* ------------------------------------------------------------------
 * main.js — Gemeinsame JS-Funktionen (Stub fuer 3.6.7a).
 *
 * Auflage 239: kein innerHTML mit Daten, addEventListener,
 *              kein eval, keine externen Bibliotheken.
 * Auflage 240: "use strict";
 * Auflage 241: nur console.debug.
 * Auflage 223: leere Stub-Funktionen, keine fetch-Aufrufe
 *              auf nicht-existente Endpunkte.
 * ------------------------------------------------------------------ */

"use strict";

(function () {
    // Stub: wird in 3.6.8+ mit echten Endpunkten gefuellt.
    function searchStub() {
        console.debug("[search] stub — noch nicht implementiert");
    }

    function init() {
        var searchInput = document.getElementById("search-input");
        if (searchInput) {
            searchInput.addEventListener("input", searchStub);
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
