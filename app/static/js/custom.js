/* DMARC Analyzer — custom JS */

// ── Dark mode toggle ──────────────────────────────────────────────────────────
(function () {
  var btn  = document.getElementById('themeToggle');
  var icon = document.getElementById('themeIcon');
  if (!btn) return;

  function current() {
    return document.documentElement.getAttribute('data-bs-theme') || 'light';
  }

  function apply(t) {
    document.documentElement.setAttribute('data-bs-theme', t);
    localStorage.setItem('dmarc-theme', t);
    if (icon) icon.className = t === 'dark' ? 'bi bi-sun' : 'bi bi-moon';
  }

  apply(current()); // sync icon to whatever the inline script already set

  btn.addEventListener('click', function () {
    apply(current() === 'dark' ? 'light' : 'dark');
  });
})();

// Auto-dismiss alerts after 6s
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.alert.alert-success').forEach(function (el) {
    setTimeout(function () {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(el);
      bsAlert.close();
    }, 6000);
  });

  // Confirm before destructive form submits
  document.querySelectorAll('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (e) {
      if (!confirm(form.dataset.confirm || 'Are you sure?')) {
        e.preventDefault();
      }
    });
  });

  // Slug auto-fill from name input
  const nameInput = document.querySelector('input[name="name"]');
  const slugInput = document.querySelector('input[name="slug"]');
  if (nameInput && slugInput && slugInput.value === '') {
    nameInput.addEventListener('input', function () {
      slugInput.value = nameInput.value
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '')
        .slice(0, 80);
    });
  }
});
