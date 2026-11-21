document.documentElement.setAttribute("data-skin", "midnight");
(function () {
  try {
    var s = localStorage.getItem("qm-skin") || "midnight";
    document.documentElement.setAttribute("data-skin", s);
    var t = localStorage.getItem("qm-theme-v32") || "light";
    if (t === "dark") document.documentElement.classList.add("dark");
    else document.documentElement.classList.remove("dark");
  } catch (e) {}
})();
