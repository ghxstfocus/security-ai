"use strict";
(function () {
    var details = document.querySelector(".user-menu");
    if (!details) return;

    document.addEventListener("click", function (event) {
        if (!details.open) return;
        if (details.contains(event.target)) return;
        details.removeAttribute("open");
    });
})();
