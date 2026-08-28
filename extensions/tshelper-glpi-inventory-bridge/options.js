'use strict';

const defaults = { enabled: true, bridgeUrl: 'http://127.0.0.1:8766', token: '' };
const enabled = document.querySelector('#enabled');
const bridgeUrl = document.querySelector('#bridgeUrl');
const token = document.querySelector('#token');
const status = document.querySelector('#status');

load();
document.querySelector('#save').addEventListener('click', save);
document.querySelector('#test').addEventListener('click', testConnection);

async function load() {
  const values = await chrome.storage.local.get(defaults);
  enabled.checked = Boolean(values.enabled);
  bridgeUrl.value = values.bridgeUrl;
  token.value = values.token;
}

async function save() {
  const values = readValues();
  await chrome.storage.local.set(values);
  showStatus('Настройки сохранены.', true);
}

async function testConnection() {
  try {
    const values = readValues();
    await chrome.storage.local.set(values);
    const response = await fetch(`${values.bridgeUrl}/health`, {
      headers: { 'X-TSHelper-Token': values.token },
      cache: 'no-store'
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) throw new Error(payload.error || `HTTP ${response.status}`);
    showStatus(`Подключение работает, bridge ${payload.bridge}.`, true);
  } catch (error) {
    showStatus(`Ошибка: ${error.message || error}`, false);
  }
}

function readValues() {
  return {
    enabled: enabled.checked,
    bridgeUrl: bridgeUrl.value.trim().replace(/\/$/, '') || defaults.bridgeUrl,
    token: token.value.trim()
  };
}

function showStatus(text, ok) {
  status.textContent = text;
  status.className = ok ? 'ok' : 'error';
}
