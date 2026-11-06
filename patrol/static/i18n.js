(function () {
  'use strict';
  var data = window.PATROL_I18N || {};
  var catalogNode = document.getElementById('patrol-i18n');
  if (catalogNode) { try { data = JSON.parse(catalogNode.textContent); } catch (_) { data = {}; } }
  window.PATROL_I18N = data;
  var messages = data.messages || {};
  var locale = normalize(data.locale);
  // These preferences affect labels/navigation only. They never unlock local
  // records, identify an account, or authorize a check-in.
  var shell = Boolean(document.documentElement.hasAttribute && document.documentElement.hasAttribute('data-offline-page'));
  var storedUI = null, queryUI = null, confirmedUI = null;
  var preferenceKey = 'patrol-ui-preferences-v1';
  function validLocale(value) { return value === 'id' || value === 'vi' || value === 'zh-Hant'; }
  function cleanPreferences(value) {
    if (!value || !validLocale(value.ui_language)) return null;
    var simple = value.simple_executor_ui === true;
    return {ui_language:value.ui_language, simple_executor_ui:simple, home_url:simple ? '/ready' : '/dashboard'};
  }
  function savePreferences(value) {
    storedUI = value;
    try { window.sessionStorage.setItem(preferenceKey, JSON.stringify(value)); } catch (_) { /* Optional presentation hint only. */ }
  }
  try { storedUI = cleanPreferences(JSON.parse(window.sessionStorage.getItem(preferenceKey))); } catch (_) { /* Private mode can deny storage. */ }
  if (shell) {
    try {
      var query = new URLSearchParams(window.location.search);
      if (validLocale(query.get('lang'))) queryUI = cleanPreferences({ui_language:query.get('lang'), simple_executor_ui:query.get('home') === 'ready'});
    } catch (_) { /* A missing hint is harmless. */ }
    locale = (queryUI || storedUI || {ui_language:locale}).ui_language;
  } else {
    var simple = Boolean(document.body && document.body.classList.contains('simple-executor-ui'));
    confirmedUI = cleanPreferences({ui_language:locale, simple_executor_ui:simple});
    savePreferences(confirmedUI);
  }
  document.documentElement.lang = locale;
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
      if (node.hasAttribute('data-i18n')) {
        var content = t(node.getAttribute('data-i18n'));
        if (node.textContent !== content) node.textContent = content;
      }
      ['title', 'placeholder', 'aria-label'].forEach(function (attr) {
        if (node.hasAttribute('data-i18n-' + attr)) {
          var value = t(node.getAttribute('data-i18n-' + attr));
          if (node.getAttribute(attr) !== value) node.setAttribute(attr, value);
        }
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
  function getPreferences(identity) {
    var identityUI = identity && cleanPreferences({ui_language:identity.ui_language,
      simple_executor_ui:identity.role === 'executor' && identity.simple_executor_ui === true});
    return confirmedUI || queryUI || identityUI || storedUI || cleanPreferences({ui_language:locale});
  }
  function acceptPreferences(value) {
    var clean = cleanPreferences(value);
    if (!clean) return false;
    confirmedUI = clean;
    savePreferences(clean);
    setLocale(clean.ui_language);
    return true;
  }
  window.PatrolI18n = {t: t, pointName: pointName, setLocale: setLocale, getLocale: function () {return locale;}, apply: apply,
    getPreferences:getPreferences, acceptPreferences:acceptPreferences};
  function initialize() {
    try { setLocale(locale); }
    finally { if (shell) document.documentElement.removeAttribute('data-offline-locale-pending'); }
  }
  if (document.readyState === 'loading') {
    if (shell && locale !== 'zh-Hant') document.documentElement.setAttribute('data-offline-locale-pending', '');
    document.addEventListener('DOMContentLoaded', initialize);
  } else initialize();
}());
