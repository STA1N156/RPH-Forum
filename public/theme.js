// Appearance for the plaza and the admin panel, using the same dark palette as RP-Hub.
// A saved choice wins, otherwise the system setting; inside RP-Hub's plaza tab the parent page decides.
(function () {
    const key = 'forum-appearance';
    const root = document.documentElement;
    const valid = value => value === 'dark' || value === 'light';
    const media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
    const system = () => (media && media.matches ? 'dark' : 'light');
    let saved = null;
    let followsParent = false;
    try { saved = localStorage.getItem(key); } catch (_) { /* Storage can be blocked; the system setting still applies. */ }

    const apply = theme => {
        root.dataset.appTheme = theme;
        window.dispatchEvent(new CustomEvent('forum-theme-change', { detail: theme }));
    };
    const applyOwn = () => { if (!followsParent) apply(valid(saved) ? saved : system()); };
    applyOwn();
    media?.addEventListener?.('change', applyOwn);
    window.addEventListener('storage', event => {
        if (event.key !== key) return;
        saved = event.newValue;
        applyOwn();
    });

    window.ForumTheme = {
        get followsParent() { return followsParent; },
        toggle() {
            if (followsParent) return;
            saved = root.dataset.appTheme === 'dark' ? 'light' : 'dark';
            try { localStorage.setItem(key, saved); } catch (_) { /* Switching still works for this visit. */ }
            apply(saved);
        }
    };

    // Embedded in RP-Hub: ask for its theme, then keep following every change it sends.
    if (window.parent !== window) {
        window.addEventListener('message', event => {
            if (event.source !== window.parent || event.data?.type !== 'RPHUB_THEME' || !valid(event.data.theme)) return;
            followsParent = true;
            apply(event.data.theme);
        });
        window.parent.postMessage({ type: 'RPH_FORUM_THEME_REQUEST' }, '*');
    }
})();
