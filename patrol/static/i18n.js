(function () {
  'use strict';
  var data = window.PATROL_I18N || {};
  var catalogNode = document.getElementById('patrol-i18n');
  if (catalogNode) { try { data = JSON.parse(catalogNode.textContent); } catch (_) { data = {}; } }
  window.PATROL_I18N = data;
  var messages = data.messages || {};
  var locale = normalize(data.locale);
  var fields = /\{([A-Za-z_][A-Za-z_0-9]*)\}/g;
  var patterns = [];
  function normalize(value) { return value === 'id' || value === 'vi' ? value : 'zh-Hant'; }
  function escapeRegex(value) { return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  Object.keys(messages).forEach(function (key) {
    var names = [], parts = [], offset = 0;
    key.replace(fields, function (match, name, index) {
      parts.push(escapeRegex(key.slice(offset, index)), '([\\s\\S]+?)');
      names.push(name); offset = index + match.length; return match;
    });
    if (names.length) {
      parts.push(escapeRegex(key.slice(offset)));
      patterns.push({re: new RegExp('^' + parts.join('') + '$'), key: key, names: names});
    }
  });
  function t(source, supplied) {
    var text = source == null ? '' : String(source), key = text, values = {};
    if (locale !== 'zh-Hant' && !Object.prototype.hasOwnProperty.call(messages, key)) {
      for (var i = 0; i < patterns.length; i += 1) {
        var p = patterns[i], match = p.re.exec(text);
        if (match) { key = p.key; p.names.forEach(function (name, n) {values[name] = match[n + 1];}); break; }
      }
    }
    Object.keys(supplied || {}).forEach(function (name) { values[name] = supplied[name]; });
    var translated = locale !== 'zh-Hant' && messages[key] && messages[key][locale] || key;
    return translated.replace(fields, function (match, name) {
      return Object.prototype.hasOwnProperty.call(values, name) ? String(values[name]) : match;
    });
  }
  function apply(root) {
    root = root || document;
    var selectors = ['[data-i18n]', '[data-i18n-title]', '[data-i18n-placeholder]', '[data-i18n-aria-label]'];
    var nodes = Array.prototype.slice.call(root.querySelectorAll(selectors.join(',')));
    if (root.matches && root.matches(selectors.join(','))) nodes.unshift(root);
    nodes.forEach(function (node) {
      if (node.hasAttribute('data-i18n')) node.textContent = t(node.getAttribute('data-i18n'));
      ['title', 'placeholder', 'aria-label'].forEach(function (attr) {
        if (node.hasAttribute('data-i18n-' + attr)) node.setAttribute(attr, t(node.getAttribute('data-i18n-' + attr)));
      });
    });
  }
  function setLocale(value) {
    var next = normalize(value), changed = next !== locale;
    locale = next;
    document.documentElement.lang = locale;
    apply(document);
    if (changed) document.dispatchEvent(new CustomEvent('patrol:locale-changed', {detail: {locale: locale}}));
  }
  function pointName(source, names) { return names && names[locale] || source; }
  window.PatrolI18n = {t: t, pointName: pointName, setLocale: setLocale, getLocale: function () {return locale;}, apply: apply};
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () {setLocale(locale);});
  else setLocale(locale);
}());
