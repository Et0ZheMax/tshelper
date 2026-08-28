'use strict';

const COLLECT_TIMEOUT_MS = 12000;
const DEFAULTS = { enabled: true, bridgeUrl: 'http://127.0.0.1:8766', token: '' };

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'TSH_INVENTORY_COLLECT_RENDERED_TAB') {
    respondAsync(sendResponse, async () => ({
      ok: true,
      computers: await collectRenderedUserTab(message.userPageUrl, message.userId)
    }));
    return true;
  }
  if (message?.type === 'TSH_INVENTORY_NEXT_JOB') {
    respondAsync(sendResponse, async () => {
      const config = await chrome.storage.local.get(DEFAULTS);
      if (!config.enabled || !config.token) return { ok: true, job: null };
      return bridgeRequest(config, '/inventory/jobs/next');
    });
    return true;
  }
  if (message?.type === 'TSH_INVENTORY_SUBMIT_RESULT') {
    respondAsync(sendResponse, async () => {
      const config = await chrome.storage.local.get(DEFAULTS);
      if (!config.enabled || !config.token) throw new Error('Расширение или токен TSHelper отключены');
      return bridgeRequest(config, '/inventory/jobs/result', {
        method: 'POST', body: JSON.stringify(message.payload || {})
      });
    });
    return true;
  }
  if (message?.type === 'TSH_INVENTORY_REPORT_PROGRESS') {
    respondAsync(sendResponse, async () => {
      const config = await chrome.storage.local.get(DEFAULTS);
      if (!config.enabled || !config.token) return { ok: false, error: 'Расширение или токен TSHelper отключены' };
      return bridgeRequest(config, '/inventory/jobs/progress', {
        method: 'POST', body: JSON.stringify(message.payload || {})
      });
    });
    return true;
  }
});

function respondAsync(sendResponse, operation) {
  operation()
    .then(sendResponse)
    .catch((error) => sendResponse({ ok: false, error: String(error?.message || error) }));
}

async function bridgeRequest(config, path, options = {}) {
  const response = await fetch(`${String(config.bridgeUrl).replace(/\/$/, '')}${path}`, {
    ...options,
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
      'X-TSHelper-Token': config.token,
      ...(options.headers || {})
    }
  });
  let payload = {};
  try { payload = await response.json(); } catch (_) {}
  if (!response.ok || !payload.ok) throw new Error(payload.error || `TSHelper HTTP ${response.status}`);
  return payload;
}

async function collectRenderedUserTab(userPageUrl, userId) {
  const helperUrl = new URL(userPageUrl);
  helperUrl.searchParams.set('tshelper_inventory_helper', '1');
  const tab = await chrome.tabs.create({ url: helperUrl.href, active: false });
  const tabId = tab.id;
  if (!tabId) throw new Error('Браузер не создал служебную вкладку GLPI');
  const startedAt = Date.now();
  try {
    while (Date.now() - startedAt < COLLECT_TIMEOUT_MS) {
      await delay(350);
      try {
        const result = await chrome.tabs.sendMessage(tabId, {
          type: 'TSH_INVENTORY_READ_RENDERED_USER_TAB',
          userId: Number(userId)
        });
        if (result?.ready && Array.isArray(result.computers)) return result.computers;
      } catch (_) {
        // Content script появится после загрузки страницы.
      }
    }
    return [];
  } finally {
    try { await chrome.tabs.remove(tabId); } catch (_) {}
  }
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
