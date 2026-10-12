(() => {
  try {
    const saved = localStorage.getItem("pve-portfw-theme");
    document.documentElement.dataset.theme = saved === "light" ? "light" : "dark";
  } catch {
    document.documentElement.dataset.theme = "dark";
  }
})();
