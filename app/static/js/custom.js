/* DMARC Analyzer — custom JS */

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
