"use strict";
(function () {
    var toggle = document.getElementById("nav-toggle");
    var sidebar = document.getElementById("sidebar");
    if (!toggle || !sidebar) return;

    function setOpen(open) {
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
        if (open) {
            sidebar.classList.add("sidebar-open");
            var first = sidebar.querySelector("a, button");
            if (first) first.focus();
        } else {
            sidebar.classList.remove("sidebar-open");
            toggle.focus();
        }
    }

    toggle.addEventListener("click", function () {
        var open = toggle.getAttribute("aria-expanded") === "true";
        setOpen(!open);
    });

    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") {
            setOpen(false);
        }
    });
})();
