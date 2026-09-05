/**
 * Minimal browser-style challenge page renderer.
 * Designed following Software Design Philosophy:
 * - 0 external web fonts or icon libraries (pure inline SVG for maximum performance and minimal payload)
 * - Native dark mode support (prefers-color-scheme)
 * - Browser error page aesthetic (clean, uncluttered, no redundant marketing texts)
 * - Loading spinner until widget loads
 * - Success feedback without layout shift
 * - Discrete bottom-right help icon with hover tooltip
 * - Failure suggestions card (with error icon) that preserves widget position
 */

import { RenderChallengeOptions } from './types';

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

interface I18nStrings {
  title: string;
  noscriptText: string;
  noscriptLinkText: string;
  retry: string;
  successWait: string;
  helpTip: string[];
  errHeading: string;
  errIntro: string;
  suggestions: { text: string; link?: { text: string; url: string }; after?: string }[];
}

function getI18nStrings(acceptLanguage?: string | null): I18nStrings {
  const lang = (acceptLanguage || '').toLowerCase();
  if (lang.includes('zh-tw') || lang.includes('zh-hk')) {
    return {
      title: '安全驗證',
      noscriptText: '繼續訪問需要啟用 JavaScript。',
      noscriptLinkText: '如何啟用它？',
      retry: '重新載入',
      successWait: '成功！正在等待瀏覽器響應...',
      helpTip: [
        '目標服務需要確認您的瀏覽器安全性。',
        '您通常不需要執行任何操作，但有時需要您點擊「我是真人」核取方塊以完成驗證。',
        '如果您遇到了故障，請參考頁面上的提示。',
        
      ],
      errHeading: '您的瀏覽器不安全。',
      errIntro: '以下是一些可能的解決方案：',
      suggestions: [
        { text: '稍後重新載入此頁面。' },
        { text: '在瀏覽器的無痕模式下重新載入，或清除快取與 Cookie 後再試。' },
        {
          text: '確認您使用的是最新版本的 ',
          link: { text: 'Chrome、Firefox 或 Edge 等瀏覽器', url: 'https://browser-update.org/update-browser.html' },
          after: '。',
        },
        { text: '暫時停用廣告攔截、安全外掛或第三方擴充功能，然後重新載入。' },
        { text: '檢查網路連線是否穩定，某些網路限制可能影響驗證。' },
        { text: '更換網路環境（例如切換至手機熱點）後重新載入頁面。' },
      ],
    };
  }
  if (lang.includes('zh')) {
    return {
      title: '安全验证',
      noscriptText: '继续访问需要启用 JavaScript。',
      noscriptLinkText: '如何启用它？',
      retry: '重新加载',
      successWait: '成功！正在等待浏览器响应...',
      helpTip: [
        '目标服务需要确认您的浏览器安全性。',
        '您通常不需要执行任何操作，但有时需要您点击“我是真人”复选框以完成验证。',
        '如果您遇到了故障，请参照页面上的提示。',
      ],
      errHeading: '您的浏览器不安全。',
      errIntro: '以下是一些可能的解决方案：',
      suggestions: [
        { text: '稍后重新加载此页面。' },
        { text: '在浏览器的无痕模式下重新加载，或清除缓存与 Cookie 后再试。' },
        {
          text: '确认您使用的是最新版本的 ',
          link: { text: 'Chrome、Firefox 或 Edge 等浏览器', url: 'https://browser-update.org/update-browser.html' },
          after: '。',
        },
        { text: '暂时停用广告拦截、安全插件或第三方扩展，然后重新加载。' },
        { text: '检查网络连接是否稳定，某些网络限制可能影响验证。' },
        { text: '更换网络环境（例如切换至手机热点）后重新加载页面。' },
      ],
    };
  }
  return {
    title: 'Security Check',
    noscriptText: 'JavaScript is required to continue.',
    noscriptLinkText: 'How to enable it?',
    retry: 'Reload',
    successWait: 'Success, waiting for browser response...',
    helpTip: [
      'The destination service needs to verify your browser security.',
      'Usually, no action is required, but you may occasionally need to check the "I am human" box.',
      'If you encounter any problems, please refer to the tips on the page.',
    ],
    errHeading: 'Your browser is not secure.',
    errIntro: 'Here are a few possible solutions:',
    suggestions: [
      { text: 'Reload this page later.' },
      { text: 'Reload in Incognito/Private mode, or clear cache and cookies.' },
      {
        text: 'Ensure you are using the latest version of ',
        link: { text: 'Chrome, Firefox, or Edge', url: 'https://browser-update.org/update-browser.html' },
        after: '.',
      },
      { text: 'Temporarily disable ad blockers, security extensions, or VPNs, then reload.' },
      { text: 'Check your internet connection stability; restrictive networks may interfere.' },
      { text: 'Switch network environments (e.g. mobile hotspot) and reload.' },
    ],
  };
}

export function renderChallengeHtml(options: RenderChallengeOptions): string {
  const {
    provider,
    siteKey = '',
    actionUrl,
    altchaChallenge,
    capEndpoint,
    capScriptUrl = 'https://cdn.jsdelivr.net/npm/@cap.js/widget',
    error,
    acceptLanguage,
  } = options;

  const i18n = getI18nStrings(acceptLanguage);
  const safeActionUrl = escapeHtml(actionUrl);
  const safeTitle = escapeHtml(i18n.title);
  const safeRetry = escapeHtml(i18n.retry);
  const safeError = error ? escapeHtml(error) : '';

  let widgetScript = '';
  let widgetMarkup = '';
  let callbackScript = '';

  if (provider === 'turnstile') {
    widgetScript = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>';
    widgetMarkup = `
      <input type="hidden" name="cf-turnstile-response" id="turnstile-input" value="">
      <div class="cf-turnstile" data-sitekey="${escapeHtml(
      siteKey || ''
    )}" data-callback="onChallengeDone" data-error-callback="onChallengeError"></div>`;
    callbackScript = `
      function onChallengeDone(token) {
        showSuccess();
        var ti = document.getElementById('turnstile-input');
        if (ti && token) ti.value = token;
        setTimeout(function() {
          document.getElementById('c-form').submit();
        }, 150);
      }
      function onChallengeError() {
        showError();
      }
      var tObserver = new MutationObserver(function() {
        var w = document.querySelector('.cf-turnstile iframe, .cf-turnstile [name="cf-turnstile-response"]');
        if (w) { hideSpinner(); tObserver.disconnect(); }
      });
      var tEl = document.querySelector('.cf-turnstile');
      if (tEl) tObserver.observe(tEl, { childList: true, subtree: true });
    `;
  } else if (provider === 'altcha') {
    widgetScript = '<script async defer src="https://gcore.jsdelivr.net/npm/altcha/dist/altcha.min.js" type="module"></script>';
    const challengeJsonStr = altchaChallenge ? JSON.stringify(altchaChallenge) : '';
    const challengeJsonAttr = challengeJsonStr ? ` challengejson='${escapeHtml(challengeJsonStr)}'` : '';
    widgetMarkup = `
      <input type="hidden" name="altcha" id="altcha-input" value="">
      <altcha-widget id="altcha-el" name="altcha" challengeurl="/_challenge/altcha"${challengeJsonAttr} hidefooter hidelogo></altcha-widget>
    `;
    callbackScript = `
      var el = document.getElementById('altcha-el');
      var form = document.getElementById('c-form');
      var input = document.getElementById('altcha-input');
      function submitAltchaWithPayload(payload) {
        if (input && payload) {
          input.value = payload;
        }
        showSuccess();
        setTimeout(function() {
          if (input && !input.value) {
            input.value = (el && (el.value || el.getAttribute('value'))) || '';
          }
          if (form) form.submit();
        }, 80);
      }
      if (el) {
        customElements.whenDefined('altcha-widget').then(hideSpinner);
        el.addEventListener('statechange', function(ev) {
          if (ev && ev.detail) {
            if (ev.detail.state === 'verified') {
              var p = ev.detail.payload || el.value || '';
              submitAltchaWithPayload(p);
            } else if (ev.detail.state === 'error') {
              showError();
            }
          }
        });
      }
      if (form) {
        form.addEventListener('submit', function() {
          if (input && !input.value && el) {
            input.value = el.value || el.getAttribute('value') || '';
          }
        });
      }
    `;
  } else if (provider === 'cap') {
    const scriptSrc = capScriptUrl || 'https://cdn.jsdelivr.net/npm/@cap.js/widget';
    widgetScript = `<script type="module" src="${escapeHtml(scriptSrc)}"></script>`;
    const cleanEndpoint = (capEndpoint || '/_challenge/cap/').replace(/\/+$/, '');
    let apiEndpoint = cleanEndpoint;
    if (!cleanEndpoint.startsWith('/_challenge') && siteKey && !cleanEndpoint.endsWith(siteKey)) {
      apiEndpoint = `${cleanEndpoint}/${siteKey}/`;
    } else {
      apiEndpoint = `${cleanEndpoint}/`;
    }

    widgetMarkup = `
      <input type="hidden" name="cap-token" id="cap-input" value="">
      <cap-widget id="cap-el" data-cap-api-endpoint="${escapeHtml(apiEndpoint)}"></cap-widget>
    `;
    callbackScript = `
      var form = document.getElementById('c-form');
      var cap = document.getElementById('cap-el');
      var capInput = document.getElementById('cap-input');
      function submitCapWithToken(token) {
        if (capInput && token) {
          capInput.value = token;
        }
        showSuccess();
        setTimeout(function() {
          if (capInput && !capInput.value && cap) {
            capInput.value = cap.value || '';
          }
          if (form) form.submit();
        }, 80);
      }
      if (cap) {
        customElements.whenDefined('cap-widget').then(hideSpinner);
        cap.addEventListener('solve', function(ev) {
          var t = (ev && ev.detail && (ev.detail.token || ev.detail.response)) || (cap && cap.value) || '';
          submitCapWithToken(t);
        });
        cap.addEventListener('cap-token', function(ev) {
          var t = (ev && ev.detail && (ev.detail.token || ev.detail.response)) || (cap && cap.value) || '';
          submitCapWithToken(t);
        });
        cap.addEventListener('error', function() {
          showError();
        });
      }
      window.addEventListener('cap:solve', function(ev) {
        var t = (ev && ev.detail && (ev.detail.token || ev.detail.response)) || (cap && cap.value) || '';
        submitCapWithToken(t);
      });
      if (form) {
        form.addEventListener('submit', function() {
          if (capInput && !capInput.value && cap) {
            capInput.value = cap.value || '';
          }
        });
      }
    `;
  }

  // Google Fonts Material Icons style SVG symbols (Info & Error)
  const errorIconSvg = `<svg class="icon-err" viewBox="0 0 24 24" width="22" height="22" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>`;
  const helpIconSvg = `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M11 18h2v-2h-2v2zm1-16C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm0-14c-2.21 0-4 1.79-4 4h2c0-1.1.9-2 2-2s2 .9 2 2c0 2-3 1.75-3 5h2c0-2.25 3-2.5 3-5 0-2.21-1.79-4-4-4z"/></svg>`;

  const suggestionsListHtml = i18n.suggestions
    .map((s) => {
      if (s.link) {
        return `<li>${escapeHtml(s.text)}<a href="${escapeHtml(s.link.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(s.link.text)}</a>${escapeHtml(s.after || '')}</li>`;
      }
      return `<li>${escapeHtml(s.text)}</li>`;
    })
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>${safeTitle}</title>
  <style>
    :root {
      --bg: #f8fafc;
      --fg: #1e293b;
      --card-bg: #ffffff;
      --border: #e2e8f0;
      --muted: #64748b;
      --err: #d93025;
      --err-bg: #fdf2f2;
      --err-border: #fecaca;
      --ok: #16a34a;
      --spin: #94a3b8;
      --link: #2563eb;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #121212;
        --fg: #e2e8f0;
        --card-bg: #1e1e1e;
        --border: #2d2d2d;
        --muted: #9ca3af;
        --err: #f87171;
        --err-bg: #271616;
        --err-border: #451a1a;
        --ok: #4ade80;
        --spin: #64748b;
        --link: #60a5fa;
      }
    }
    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      padding: 0;
      min-height: 100vh;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--fg);
      overflow-x: hidden;
    }
    body {
      position: relative;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: flex-start;
      min-height: 100vh;
      padding: 24px 16px 80px 16px;
    }
    /* Fixed viewport spacer to ensure widget is centered when page loads, while allowing scroll on mobile when error card expands */
    .viewport-spacer {
      flex: 1 1 0%;
      min-height: 20px;
      max-height: calc(50vh - 120px);
    }
    .widget-area {
      width: 100%;
      max-width: 480px;
      display: flex;
      flex-direction: column;
      align-items: center;
      position: relative;
      z-index: 10;
    }
    .widget-container {
      position: relative;
      width: 100%;
      max-width: 320px;
      min-height: 65px;
      display: flex;
      justify-content: center;
      align-items: center;
    }
    .spinner {
      position: absolute;
      width: 28px;
      height: 28px;
      border: 3px solid rgba(148, 163, 184, 0.2);
      border-top-color: var(--spin);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      pointer-events: none;
      z-index: 1;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    .msg-status {
      font-size: 13px;
      margin-top: 12px;
      text-align: center;
      min-height: 20px;
    }
    .msg-success {
      color: var(--ok);
      display: none;
    }
    /* Failure suggestions card: smoothly appears under widget without altering its origin */
    .err-card {
      width: 100%;
      margin-top: 24px;
      background: var(--card-bg);
      border: 1px solid var(--err-border);
      border-radius: 8px;
      padding: 16px 20px;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08);
      font-size: 13px;
      line-height: 1.6;
      word-break: break-word;
    }
    .err-header {
      display: flex;
      align-items: center;
      gap: 8px;
      font-weight: 600;
      color: var(--err);
      margin-bottom: 6px;
    }
    .err-header svg {
      flex-shrink: 0;
    }
    .err-desc {
      color: var(--muted);
      margin: 0 0 8px 0;
    }
    .err-tips {
      margin: 0;
      padding-left: 20px;
      color: var(--fg);
    }
    .err-tips li {
      margin-bottom: 6px;
    }
    .err-tips a {
      color: var(--link);
      text-decoration: underline;
      text-underline-offset: 2px;
    }
    .err-raw {
      margin-top: 10px;
      padding-top: 8px;
      border-top: 1px dashed var(--border);
      font-size: 12px;
      color: var(--err);
    }
    .err-raw a {
      color: inherit;
      text-decoration: underline;
      margin-left: 6px;
    }
    /* Discrete help icon at bottom right */
    .help-btn {
      position: fixed;
      bottom: 16px;
      right: 16px;
      width: 36px;
      height: 36px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--muted);
      cursor: help;
      opacity: 0.75;
      transition: opacity 0.2s, color 0.2s;
      z-index: 50;
      background: var(--card-bg);
      border: 1px solid var(--border);
      box-shadow: 0 2px 6px rgba(0,0,0,0.06);
    }
    .help-btn:hover {
      opacity: 1;
      color: var(--fg);
    }
    .tooltip {
      position: absolute;
      bottom: calc(100% + 10px);
      right: 0;
      background: var(--fg);
      color: var(--bg);
      padding: 10px 14px;
      border-radius: 6px;
      font-size: 12px;
      line-height: 1.5;
      white-space: normal;
      width: max-content;
      max-width: min(300px, calc(100vw - 40px));
      pointer-events: none;
      opacity: 0;
      transform: translateY(4px);
      transition: opacity 0.2s, transform 0.2s;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
      text-align: left;
    }
    .tooltip p {
      margin: 0;
    }
    .tooltip p + p {
      margin-top: 6px;
    }
    .help-btn:hover .tooltip,
    .help-btn:focus .tooltip {
      opacity: 1;
      transform: translateY(0);
    }
    noscript .ns-notice {
      color: var(--err);
      font-size: 13px;
      margin-top: 14px;
      text-align: center;
      line-height: 1.5;
    }
    noscript .ns-notice a {
      color: var(--link);
      text-decoration: underline;
      margin-left: 4px;
    }
  </style>
  ${widgetScript}
</head>
<body>
  <div class="viewport-spacer"></div>
  <div class="widget-area">
    <form id="c-form" method="POST" action="${safeActionUrl}">
      <div class="widget-container">
        <div id="loading-spinner" class="spinner"></div>
        ${widgetMarkup}
      </div>
      <div id="success-msg" class="msg-status msg-success">${escapeHtml(i18n.successWait)}</div>
      <noscript>
        <div class="ns-notice">
          ${escapeHtml(i18n.noscriptText)}
          <a href="https://www.enablejavascript.io/" target="_blank" rel="noopener noreferrer">${escapeHtml(i18n.noscriptLinkText)}</a>
        </div>
      </noscript>
    </form>
    <div id="err-msg" class="err-card" style="${error ? '' : 'display:none;'}">
      <div class="err-header">
        ${errorIconSvg}
        <span>${escapeHtml(i18n.errHeading)}</span>
      </div>
      <p class="err-desc">${escapeHtml(i18n.errIntro)}</p>
      <ul class="err-tips">
        ${suggestionsListHtml}
      </ul>
      <div class="err-raw">${safeError} <a href="${safeActionUrl}">${safeRetry}</a></div>
    </div>
  </div>

  <div class="help-btn" aria-label="Help" tabindex="0">
    ${helpIconSvg}
    <div class="tooltip">
      ${i18n.helpTip.map((line) => `<p>${escapeHtml(line)}</p>`).join('')}
    </div>
  </div>

  <script>
    function hideSpinner() {
      var sp = document.getElementById('loading-spinner');
      if (sp) sp.style.display = 'none';
    }
    function showSuccess() {
      hideSpinner();
      var sm = document.getElementById('success-msg');
      if (sm) sm.style.display = 'block';
    }
    function showError() {
      hideSpinner();
      var err = document.getElementById('err-msg');
      if (err) err.style.display = 'block';
    }
    window.addEventListener('load', function() {
      setTimeout(hideSpinner, 3500);
    });
    ${callbackScript}
  </script>
</body>
</html>`;
}

