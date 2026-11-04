// QCCheck – Installationsseite: Sprache (Englisch Vorgabe, Deutsch), einfacher Zugang, Zeilen kopieren.
// Der Zugang ist bewusst nur eine Schwelle (Marc: „damit nicht jeder darauf landet“): verglichen wird der SHA-256 des
// eingegebenen Codes, freigeschaltet bleibt es per localStorage. Die Pakete selbst sind öffentlich und signiert.
(() => {
  "use strict";
  const HASH = "f5f9de6febfcd4935ca6d47d682115b70d70765944530f9e9fcfa7a611e16a0a";
  const store = { get: (k) => { try { return localStorage.getItem(k); } catch { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* egal */ } } };
  const $ = (id) => document.getElementById(id);

  // Sprache: ?lang=de|en, sonst gespeichert, sonst Englisch
  function setLang(l) {
    const lang = l === "de" ? "de" : "en";
    document.documentElement.dataset.lang = lang;
    document.documentElement.lang = lang;
    document.querySelectorAll("[data-lang-switch]").forEach((b) => { b.textContent = lang === "de" ? "English" : "Deutsch"; });
    const code = $("gate-code");
    if (code) { code.placeholder = lang === "de" ? "Zugangscode" : "Access code"; code.setAttribute("aria-label", code.placeholder); }
    document.querySelectorAll(".copy").forEach((b) => { if (!b.classList.contains("done")) b.textContent = lang === "de" ? "Kopieren" : "Copy"; });
    store.set("qcLang", lang);
  }
  setLang(new URLSearchParams(location.search).get("lang") || store.get("qcLang") || "en");
  document.querySelectorAll("[data-lang-switch]").forEach((b) => b.addEventListener("click", () => setLang(document.documentElement.dataset.lang === "de" ? "en" : "de")));
  const de = () => document.documentElement.dataset.lang === "de";

  // Zugang
  async function sha256(text) {
    const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  function open() { $("gate").hidden = true; $("page").hidden = false; }
  if (store.get("qcAccess") === HASH) open();
  $("gate-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const h = await sha256($("gate-code").value.trim());
    if (h === HASH) { store.set("qcAccess", HASH); $("gate-err").hidden = true; open(); }
    else { $("gate-err").hidden = false; $("gate-code").select(); }
  });

  // Installationszeilen kopieren (Knopf oder Klick auf die Zeile); wo die Zwischenablage verweigert wird: markieren
  async function copy(code, button) {
    try { await navigator.clipboard.writeText(code.textContent.trim()); button.textContent = de() ? "Kopiert" : "Copied"; }
    catch {
      const r = document.createRange(); r.selectNodeContents(code);
      const s = getSelection(); s.removeAllRanges(); s.addRange(r);
      button.textContent = de() ? "Markiert" : "Selected";
    }
    button.classList.add("done");
    setTimeout(() => { button.classList.remove("done"); button.textContent = de() ? "Kopieren" : "Copy"; }, 1800);
  }
  for (const box of document.querySelectorAll(".copyable")) {
    const code = box.querySelector("code"), button = box.querySelector(".copy");
    button.addEventListener("click", () => copy(code, button));
    code.addEventListener("click", () => { if (!String(getSelection())) copy(code, button); });
  }
})();
