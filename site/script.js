// Foxly Child Protection – kleine Helfer ohne externe Abhängigkeiten.
document.getElementById("year").textContent = new Date().getFullYear();

// Kopier-Buttons: data-copy enthält den Text, data-copy-target die ID eines Elements.
for (const button of document.querySelectorAll(".copy")) {
  button.addEventListener("click", async () => {
    const target = button.dataset.copyTarget && document.getElementById(button.dataset.copyTarget);
    const text = button.dataset.copy || (target ? target.innerText : "");
    const label = button.textContent;
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = "Kopiert";
    } catch {
      button.textContent = "Nicht möglich";
    }
    setTimeout(() => { button.textContent = label; }, 1600);
  });
}

// Statusanzeige: Die Seite wird nur bei erfolgreicher Aktualisierung neu erzeugt.
// Liegt diese länger als 26 Stunden zurück, ist mindestens ein Lauf ausgefallen.
const generated = new Date(document.body.dataset.generated);
const status = document.getElementById("status");
if (!Number.isNaN(generated.getTime()) && status) {
  const hours = Math.max(0, Math.round((Date.now() - generated) / 36e5));
  const age = hours < 1 ? "vor weniger als einer Stunde" : hours < 48 ? `vor ${hours} Std.` : `vor ${Math.round(hours / 24)} Tagen`;
  const stale = hours > 26;
  status.classList.toggle("stale", stale);
  document.getElementById("status-text").textContent = stale ? `Veraltet · letzte Aktualisierung ${age}` : `Aktuell · aktualisiert ${age}`;
}
