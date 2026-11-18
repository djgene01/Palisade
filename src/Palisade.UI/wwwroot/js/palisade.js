window.palisade = {
    // Opens a brand-new connection on the second port. The page's own connection keeps working even
    // when a new rule would block the next visit, so only a fresh connection proves the owner is not locked out.
    checkReachable: async function (port) {
        for (let attempt = 0; attempt < 3; attempt++) {
            const abort = new AbortController();
            const timer = setTimeout(() => abort.abort(), 2500);
            try {
                await fetch(`${location.protocol}//${location.hostname}:${port}/ping?t=${Date.now()}`,
                    { mode: "no-cors", cache: "no-store", signal: abort.signal });
                return true;
            } catch {
                await new Promise(resolve => setTimeout(resolve, 700));
            } finally {
                clearTimeout(timer);
            }
        }
        return false;
    },

    whoAmI: async function () {
        try {
            const response = await fetch("/api/whoami", { cache: "no-store" });
            return response.ok ? await response.text() : "";
        } catch {
            return "";
        }
    },

    isDark: function () {
        return document.documentElement.classList.contains("dark");
    },

    toggleTheme: function () {
        const dark = document.documentElement.classList.toggle("dark");
        try { localStorage.setItem("palisade-theme", dark ? "dark" : "light"); } catch { }
        return dark;
    }
};
