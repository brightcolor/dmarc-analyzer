/* DMARC Analyzer: behaviour of the workbench frame and small page helpers. */
(function () {
  'use strict';

  var root = document.documentElement;

  // Light and dark: the pressed button shows the current mode, the choice is remembered.
  var modeButtons = document.querySelectorAll('.bc-mode [data-mode]');
  function showMode(mode) {
    root.setAttribute('data-theme', mode);
    modeButtons.forEach(function (b) { b.setAttribute('aria-pressed', String(b.dataset.mode === mode)); });
  }
  if (modeButtons.length) {
    showMode(root.getAttribute('data-theme') || 'light');
    modeButtons.forEach(function (b) {
      b.addEventListener('click', function () {
        showMode(b.dataset.mode);
        try { localStorage.setItem('bc-theme', b.dataset.mode); } catch (e) {}
      });
    });
  }

  // Rail accordion: one module open at a time; a click on the open one folds it.
  var items = document.querySelectorAll('button.bc-rail__item');
  items.forEach(function (item) {
    item.addEventListener('click', function () {
      var open = item.getAttribute('aria-expanded') === 'true';
      items.forEach(function (other) {
        other.setAttribute('aria-expanded', 'false');
        var sub = document.getElementById(other.getAttribute('aria-controls'));
        if (sub) sub.hidden = true;
      });
      item.setAttribute('aria-expanded', String(!open));
      var mine = document.getElementById(item.getAttribute('aria-controls'));
      if (mine) mine.hidden = open;
    });
  });

  // Narrow screens: the menu button slides the rail in and hands it the focus;
  // Escape or a tap on the shade closes it and gives the focus back.
  var app = document.querySelector('.bc-app');
  var burger = document.querySelector('.bc-burger');
  var shade = document.querySelector('.bc-shade');
  if (app && burger && shade) {
    var rail = function (open) {
      app.setAttribute('data-rail', open ? 'open' : 'closed');
      burger.setAttribute('aria-expanded', String(open));
      shade.hidden = !open;
      if (open) {
        var first = document.querySelector('.bc-rail__item');
        if (first) first.focus();
      } else {
        burger.focus();
      }
    };
    burger.addEventListener('click', function () { rail(app.getAttribute('data-rail') !== 'open'); });
    shade.addEventListener('click', function () { rail(false); });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && app.getAttribute('data-rail') === 'open') rail(false);
    });
  }

  // Forms with data-confirm ask before a destructive action.
  document.querySelectorAll('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (e) {
      if (!window.confirm(form.dataset.confirm)) e.preventDefault();
    });
  });

  // Fields that belong to one choice: data-show-for lists the values of the select marked data-switch.
  document.querySelectorAll('select[data-switch]').forEach(function (select) {
    var form = select.form;
    if (!form) return;
    var update = function () {
      form.querySelectorAll('[data-show-for]').forEach(function (group) {
        var show = group.dataset.showFor.split(' ').indexOf(select.value) !== -1;
        group.hidden = !show;
        group.querySelectorAll('input, textarea, select').forEach(function (field) { field.disabled = !show; });
      });
    };
    select.addEventListener('change', update);
    update();
  });

  // Copy buttons: data-copy holds the id of the element whose text is copied.
  document.querySelectorAll('[data-copy]').forEach(function (button) {
    var label = button.querySelector('.app-copy-label');
    var original = label ? label.textContent : '';
    button.addEventListener('click', function () {
      var source = document.getElementById(button.dataset.copy);
      if (!source || !navigator.clipboard) return;
      var text = 'value' in source ? source.value : source.textContent;
      navigator.clipboard.writeText(text.trim()).then(function () {
        if (label) {
          label.textContent = 'Kopiert';
          setTimeout(function () { label.textContent = original; }, 2000);
        }
      }, function () {
        if (label) label.textContent = 'Bitte markieren und kopieren';
      });
    });
  });

  // Slug follows the name until someone edits the slug.
  var nameInput = document.querySelector('input[name="name"][data-slug-source]');
  var slugInput = document.querySelector('input[name="slug"]');
  if (nameInput && slugInput && slugInput.value === '') {
    nameInput.addEventListener('input', function () {
      slugInput.value = nameInput.value.toLowerCase()
        .replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue').replace(/ß/g, 'ss')
        .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 80);
    });
  }

  // Password fields: show and hide, generate, rate the strength.
  document.querySelectorAll('[data-password-toggle]').forEach(function (button) {
    button.addEventListener('click', function () {
      var input = document.getElementById(button.dataset.passwordToggle);
      if (!input) return;
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      button.setAttribute('aria-pressed', String(show));
    });
  });

  var CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.:!?';
  document.querySelectorAll('[data-password-generate]').forEach(function (button) {
    button.addEventListener('click', function () {
      var target = document.getElementById(button.dataset.passwordGenerate);
      var repeat = document.getElementById(button.dataset.passwordRepeat || '');
      if (!target || !window.crypto) return;
      var length = parseInt(button.dataset.passwordLength || '20', 10);
      var bytes = new Uint32Array(length);
      window.crypto.getRandomValues(bytes);
      var value = '';
      for (var i = 0; i < length; i++) value += CHARSET[bytes[i] % CHARSET.length];
      target.type = 'text';
      target.value = value;
      if (repeat) { repeat.type = 'text'; repeat.value = value; }
      target.dispatchEvent(new Event('input'));
    });
  });

  var LEVELS = ['', 'sehr schwach', 'schwach', 'mittel', 'stark', 'sehr stark'];
  document.querySelectorAll('[data-password-strength]').forEach(function (meter) {
    var input = document.getElementById(meter.dataset.passwordStrength);
    var text = document.getElementById(meter.dataset.strengthText);
    var minimum = parseInt(meter.dataset.minLength || '10', 10);
    if (!input) return;
    input.addEventListener('input', function () {
      var v = input.value;
      var classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(function (r) { return r.test(v); }).length;
      var level = 0;
      if (v.length > 0) level = 1;
      if (v.length >= minimum) level = 2;
      if (v.length >= minimum && classes >= 3) level = 3;
      if (v.length >= minimum + 4 && classes >= 3) level = 4;
      if (v.length >= minimum + 10 && classes >= 3) level = 5;
      if (/^(.)\1+$/.test(v)) level = Math.min(level, 1);
      meter.setAttribute('data-level', String(level));
      if (text) {
        text.textContent = v.length === 0 ? '' :
          (v.length < minimum ? 'Noch ' + (minimum - v.length) + ' Zeichen bis zur Mindestlänge' : 'Stärke: ' + LEVELS[level]);
      }
    });
  });
})();
