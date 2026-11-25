document.documentElement.setAttribute("data-skin", "prism");
document.documentElement.setAttribute("data-motion", "full");
document.documentElement.classList.add("dark");
(function () {
  try {
    var darkOnly = { prism: 1, obsidian: 1, radar: 1, phosphor: 1, blueprint: 1, synthwave: 1 };
    var s = localStorage.getItem("qm-skin") || "prism";
    document.documentElement.setAttribute("data-skin", s);
    var t = localStorage.getItem("qm-theme-v32");
    var isDark = Boolean(darkOnly[s]) || t === "dark";
    if (isDark) document.documentElement.classList.add("dark");
    else document.documentElement.classList.remove("dark");
    var m = localStorage.getItem("qm-motion") || "full";
    if (m !== "full" && m !== "balanced" && m !== "reduced") m = "full";
    document.documentElement.setAttribute("data-motion", m);
  } catch (e) {}
})();
