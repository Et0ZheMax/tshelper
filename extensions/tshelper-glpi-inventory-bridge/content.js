'use strict';

(() => {
  const PARSER_VERSION = '0.1.0';
  const POLL_MS = 3000;
  const IDLE_POLL_MS = 5000;
  if (window.__TSHELPER_GLPI_INVENTORY_BRIDGE__) return;
  window.__TSHELPER_GLPI_INVENTORY_BRIDGE__ = PARSER_VERSION;
  const renderedPageStartedAt = Date.now();

  class SessionRequiredError extends Error {}

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type !== 'TSH_INVENTORY_READ_RENDERED_USER_TAB') return;
    const expectedId = Number(message.userId) || 0;
    const currentId = Number(new URLSearchParams(location.search).get('id')) || 0;
    if (expectedId && currentId !== expectedId) {
      sendResponse({ ready: false, computers: [] });
      return;
    }
    const parsed = parseComputerRows(document);
    if (parsed.length) {
      sendResponse({ ready: true, computers: parsed });
      return;
    }
    const usedTab = findUsedTabLink(document);
    if (usedTab && !usedTab.dataset.tshelperInventoryClicked) {
      usedTab.dataset.tshelperInventoryClicked = '1';
      try { usedTab.click(); } catch (_) {}
    }
    sendResponse({ ready: Date.now() - renderedPageStartedAt > 6500, computers: [] });
  });

  if (new URLSearchParams(location.search).get('tshelper_inventory_helper') === '1') return;
  pollLoop();

  async function pollLoop() {
    let delay = IDLE_POLL_MS;
    try {
      const next = await chrome.runtime.sendMessage({ type: 'TSH_INVENTORY_NEXT_JOB' });
      if (!next?.ok) throw new Error(next?.error || 'Service worker не получил задание');
      if (next.job) {
        delay = POLL_MS;
        const result = await processJob(next.job);
        const submitted = await chrome.runtime.sendMessage({
          type: 'TSH_INVENTORY_SUBMIT_RESULT',
          payload: { job_id: next.job.id, ...result }
        });
        if (!submitted?.ok) throw new Error(submitted?.error || 'Service worker не сохранил результат');
      }
    } catch (error) {
      console.debug('[TSHelper Inventory] Пауза обработки очереди:', error?.message || error);
    }
    setTimeout(pollLoop, delay);
  }

  async function processJob(job) {
    const base = {
      login: normalizeLogin(job.login),
      checked_at: new Date().toISOString(),
      parser_version: PARSER_VERSION,
      computers: []
    };
    try {
      const user = await resolveExactUser(job);
      if (!user) return { ...base, status: 'not_found', resolution: 'exact-login' };
      if (user.ambiguous) return { ...base, status: 'ambiguous', resolution: 'exact-login' };

      const rows = await loadUsedComputers(user.id);
      if (!rows.length) {
        return {
          ...base,
          status: 'no_computers',
          resolution: 'exact-login',
          glpi_user_id: user.id,
          glpi_name: user.name || ''
        };
      }
      const computers = await mapWithConcurrency(rows, 3, enrichComputer);
      return {
        ...base,
        status: 'ok',
        resolution: 'exact-login',
        glpi_user_id: user.id,
        glpi_name: user.name || '',
        computers
      };
    } catch (error) {
      const sessionRequired = error instanceof SessionRequiredError;
      return {
        ...base,
        status: sessionRequired ? 'session_required' : 'error',
        error: String(error?.message || error).slice(0, 500)
      };
    }
  }

  async function resolveExactUser(job) {
    const wanted = normalizeLogin(job.login);
    const knownId = Number(job.glpi_user_id) || 0;
    if (knownId) {
      const known = await fetchUserIdentity(knownId);
      if (normalizeLogin(known.login) === wanted) return known;
    }

    const descriptor = await loadUserSearchDescriptor();
    const candidates = await searchUsers(wanted, descriptor);
    const verified = [];
    for (const candidate of candidates.slice(0, 10)) {
      try {
        const identity = await fetchUserIdentity(candidate.id);
        if (normalizeLogin(identity.login) === wanted) verified.push(identity);
      } catch (error) {
        if (error instanceof SessionRequiredError) throw error;
        console.debug('[TSHelper Inventory] Не удалось проверить User', candidate.id, error);
      }
    }
    if (verified.length === 1) return verified[0];
    if (verified.length > 1) return { ambiguous: true };
    return null;
  }

  async function fetchUserIdentity(userId) {
    const { doc, shellDoc } = await fetchFormDocument('User', userId);
    const loginField = doc.querySelector('input[name="name"], select[name="name"]');
    const login = String(loginField?.value || '').trim();
    if (!login) throw new Error(`User #${userId}: login не найден`);
    const title = String(shellDoc.querySelector('title')?.textContent || '').replace(/\s+/g, ' ').trim();
    const titleMatch = title.match(/(?:Пользователь|User)\s*-\s*(.*?)\s*-\s*ID\s+\d+/i);
    return { id: Number(userId), login, name: titleMatch?.[1]?.trim() || '' };
  }

  async function loadUserSearchDescriptor() {
    const response = await fetch('/front/ticket.form.php', {
      credentials: 'same-origin', cache: 'no-store', redirect: 'follow'
    });
    const html = await response.text();
    ensureSession(response, html);
    const doc = parseHtml(html);
    const requester = doc.querySelector('select[data-actor-type="requester"]');
    const requesterId = requester?.id || '';
    const scripts = [...doc.querySelectorAll('script')].map((item) => item.textContent || '');
    const script = scripts.find((text) => requesterId && text.includes(`actor_select = $("#${requesterId}")`) && text.includes('/ajax/actors.php'))
      || scripts.find((text) => /(actorytype|actortype)/.test(text) && text.includes('/ajax/actors.php'));
    const idorToken = script?.match(/_idor_token\s*:\s*['"]([^'"]+)['"]/)?.[1] || '';
    if (!script || !idorToken) throw new Error('GLPI: не найдены параметры поиска пользователей');
    const item = extractJsonObjectAfter(script, 'item:') || {};
    return {
      csrf: getCsrf(doc),
      idorToken,
      usersRight: script.match(/users_right\s*:\s*['"]([^'"]+)['"]/)?.[1] || 'all',
      entityRestrict: Number(item.entities_id ?? 0),
      itiltemplateClass: script.match(/itiltemplate_class\s*:\s*['"]([^'"]+)['"]/)?.[1] || 'TicketTemplate',
      itiltemplatesId: Number(script.match(/itiltemplates_id\s*:\s*(\d+)/)?.[1]) || 0,
      item
    };
  }

  async function searchUsers(query, descriptor) {
    const body = new URLSearchParams();
    const payload = {
      action: 'getActors', actortype: 'requester', users_right: descriptor.usersRight,
      entity_restrict: descriptor.entityRestrict, searchText: query,
      _idor_token: descriptor.idorToken, itiltemplate_class: descriptor.itiltemplateClass,
      itiltemplates_id: descriptor.itiltemplatesId, itemtype: 'Ticket', items_id: 0,
      item: descriptor.item, returned_itemtypes: ['User'], page: 1
    };
    Object.entries(payload).forEach(([key, value]) => appendFormValue(body, key, value));
    const response = await fetch('/ajax/actors.php', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'X-Glpi-Csrf-Token': descriptor.csrf
      },
      body: body.toString()
    });
    const text = await response.text();
    ensureSession(response, text);
    if (!response.ok) throw new Error(`Поиск пользователя GLPI: HTTP ${response.status}`);
    let data;
    try { data = JSON.parse(text); } catch (_) { throw new Error('GLPI вернул некорректный ответ поиска'); }
    return flattenUserResults(data?.results ?? data);
  }

  function flattenUserResults(input) {
    const result = [];
    const seen = new Set();
    const visit = (value) => {
      if (Array.isArray(value)) return value.forEach(visit);
      if (!value || typeof value !== 'object') return;
      const itemtype = value.itemtype || value.type || '';
      let id = Number(value.items_id || value.users_id || 0);
      if (!id && typeof value.id === 'string') id = Number(value.id.match(/^User[_:-](\d+)$/i)?.[1] || 0);
      else if (!id) id = Number(value.id) || 0;
      if (/^User$/i.test(String(itemtype)) && id > 0 && !seen.has(id)) {
        seen.add(id);
        result.push({ id });
      }
      visit(value.children);
      visit(value.results);
    };
    visit(input);
    return result;
  }

  async function loadUsedComputers(userId) {
    const userPageUrl = `/front/user.form.php?id=${encodeURIComponent(userId)}&forcetab=${encodeURIComponent('User$1')}`;
    const response = await fetch(userPageUrl, {
      credentials: 'same-origin', cache: 'no-store', redirect: 'follow'
    });
    const html = await response.text();
    ensureSession(response, html);
    if (!response.ok) throw new Error(`User #${userId}: HTTP ${response.status}`);
    const doc = parseHtml(html);
    const direct = parseComputerRows(doc);
    if (direct.length) return direct;

    const usedTab = findUsedTabLink(doc);
    let tabUrl = usedTab?.getAttribute('data-glpi-ajax-content') || '';
    if (!tabUrl) {
      const params = new URLSearchParams({
        _glpi_tab: 'User$1', name: '', formoptions: 'data-track-changes=true',
        _target: '/front/user.form.php', _itemtype: 'User', id: String(userId)
      });
      tabUrl = `/ajax/common.tabs.php?${params}`;
    }
    try {
      const tabResponse = await fetch(new URL(tabUrl, location.origin), {
        credentials: 'same-origin', cache: 'no-store', redirect: 'follow',
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
      });
      const tabHtml = await tabResponse.text();
      ensureSession(tabResponse, tabHtml);
      const parsed = parseComputerRows(parseHtml(tabHtml));
      if (parsed.length) return parsed;
    } catch (error) {
      if (error instanceof SessionRequiredError) throw error;
      console.debug('[TSHelper Inventory] AJAX User$1 не сработал:', error);
    }
    return collectViaRenderedTab(userPageUrl, userId);
  }

  function findUsedTabLink(doc) {
    return [...doc.querySelectorAll('a[data-glpi-ajax-content], a[href*="forcetab="]')].find((anchor) => {
      const value = `${anchor.getAttribute('data-glpi-ajax-content') || ''} ${anchor.getAttribute('href') || ''}`;
      const text = String(anchor.textContent || '').replace(/\s+/g, ' ').trim();
      return /User(?:%24|\$)1/i.test(value) || /^(Использует|Used items)$/i.test(text);
    });
  }

  function parseComputerRows(doc) {
    const result = [];
    const seen = new Set();
    for (const row of doc.querySelectorAll('tr[data-itemtype], tr[data-id]')) {
      let itemtype = String(row.getAttribute('data-itemtype') || '').trim();
      let id = Number(row.getAttribute('data-id')) || 0;
      const checkboxMatch = row.querySelector('input[name^="item["]')?.name?.match(/^item\[([^\]]+)\]\[(\d+)\]$/);
      if ((!itemtype || !id) && checkboxMatch) {
        itemtype ||= checkboxMatch[1];
        id ||= Number(checkboxMatch[2]);
      }
      const formLink = row.querySelector('a[href*="computer.form.php"][href*="id="]');
      if (!id && formLink) id = Number(new URL(formLink.href, location.origin).searchParams.get('id')) || 0;
      if (itemtype !== 'Computer' || !id || seen.has(id)) continue;
      const texts = [...row.querySelectorAll(':scope > td')].map((cell) => String(cell.textContent || '').replace(/\s+/g, ' ').trim());
      const relation = texts.filter(Boolean).at(-1) || '';
      if (!/^(Пользователь|User)$/i.test(relation)) continue;
      seen.add(id);
      result.push({
        itemtype: 'Computer', id,
        name: String(formLink?.textContent || texts[3] || '').replace(/\s+/g, ' ').trim(),
        serial: texts[4] || '', inventory: texts[5] || '', status: texts[6] || '', relation
      });
    }
    return result;
  }

  function collectViaRenderedTab(userPageUrl, userId) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({
        type: 'TSH_INVENTORY_COLLECT_RENDERED_TAB',
        userPageUrl: new URL(userPageUrl, location.origin).href,
        userId: Number(userId)
      }, (response) => {
        if (chrome.runtime.lastError || !response?.ok) return resolve([]);
        resolve(Array.isArray(response.computers) ? response.computers : []);
      });
    });
  }

  async function enrichComputer(row) {
    try {
      const { doc, shellDoc } = await fetchFormDocument('Computer', row.id);
      const hostname = readComputerName(doc) || row.name;
      const osName = await readOperatingSystem(doc, shellDoc);
      return {
        ...row,
        hostname,
        serial: readFormValue(doc, 'input[name="serial"]') || row.serial,
        inventory: readFormValue(doc, 'input[name="otherserial"]') || row.inventory,
        status: readSelectedText(doc, 'select[name="states_id"]') || row.status,
        os: osName,
        os_family: classifyOs(osName || hostname)
      };
    } catch (error) {
      if (error instanceof SessionRequiredError) throw error;
      return { ...row, hostname: row.name, os: '', os_family: classifyOs(row.name) };
    }
  }

  async function fetchFormDocument(itemtype, id) {
    const path = itemtype === 'User' ? '/front/user.form.php' : '/front/computer.form.php';
    const response = await fetch(`${path}?id=${encodeURIComponent(id)}&forcetab=${encodeURIComponent(`${itemtype}$main`)}`, {
      credentials: 'same-origin', cache: 'no-store', redirect: 'follow'
    });
    const html = await response.text();
    ensureSession(response, html);
    if (!response.ok) throw new Error(`${itemtype} #${id}: HTTP ${response.status}`);
    const shellDoc = parseHtml(html);
    let doc = shellDoc;
    if (!doc.querySelector('input[name="name"], select[name="name"]')) {
      const mainTab = [...shellDoc.querySelectorAll('a[data-glpi-ajax-content]')].find((anchor) => {
        const value = `${anchor.getAttribute('href') || ''} ${anchor.getAttribute('data-glpi-ajax-content') || ''}`;
        return new RegExp(`${itemtype}(?:%24|\\$)main`, 'i').test(value);
      }) || shellDoc.querySelector('a[data-glpi-ajax-content]');
      const ajaxUrl = mainTab?.getAttribute('data-glpi-ajax-content');
      if (ajaxUrl) {
        const tabResponse = await fetch(new URL(ajaxUrl, location.origin), {
          credentials: 'same-origin', cache: 'no-store', redirect: 'follow',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const tabHtml = await tabResponse.text();
        ensureSession(tabResponse, tabHtml);
        if (tabResponse.ok) doc = parseHtml(tabHtml);
      }
    }
    return { doc, shellDoc, response };
  }

  function readComputerName(doc) {
    const field = doc.querySelector('input[name="name"], select[name="name"]');
    return String(field?.value || '').trim();
  }

  function readFormValue(doc, selector) {
    return String(doc.querySelector(selector)?.value || '').replace(/\s+/g, ' ').trim();
  }

  function readSelectedText(doc, selector) {
    const field = doc.querySelector(selector);
    return String(field?.selectedOptions?.[0]?.textContent || field?.value || '').replace(/\s+/g, ' ').trim();
  }

  async function readOperatingSystem(doc, shellDoc = doc) {
    const direct = readOsFromDocument(doc);
    if (direct) return direct;
    const links = [...shellDoc.querySelectorAll('a[data-glpi-ajax-content], a[href*="forcetab="]')].filter((anchor) => {
      const value = `${anchor.textContent || ''} ${anchor.getAttribute('href') || ''} ${anchor.getAttribute('data-glpi-ajax-content') || ''}`;
      return /(операционн|operating.?system|Item_OperatingSystem)/i.test(value);
    });
    for (const link of links.slice(0, 3)) {
      const url = link.getAttribute('data-glpi-ajax-content') || link.getAttribute('href');
      if (!url) continue;
      try {
        const response = await fetch(new URL(url, location.origin), {
          credentials: 'same-origin', cache: 'no-store',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const html = await response.text();
        ensureSession(response, html);
        const found = readOsFromDocument(parseHtml(html));
        if (found) return found;
      } catch (error) {
        if (error instanceof SessionRequiredError) throw error;
      }
    }
    return '';
  }

  function readOsFromDocument(doc) {
    const field = doc.querySelector(
      'select[name*="operatingsystem" i], input[name*="operatingsystem" i], select[name*="operating_system" i], input[name*="operating_system" i]'
    );
    if (field) {
      const selected = field.selectedOptions?.[0]?.textContent || field.value;
      if (selected && String(selected).trim() !== '-----') return String(selected).replace(/\s+/g, ' ').trim();
    }
    const text = String(doc.body?.innerText || '').replace(/\s+/g, ' ');
    const match = text.match(/\b(Windows(?: Server)?\s*[A-Za-z0-9. ()_-]{0,45}|Ubuntu\s*[A-Za-z0-9. _-]{0,30}|Debian\s*[A-Za-z0-9. _-]{0,30}|Astra Linux\s*[A-Za-z0-9. _-]{0,30}|ALT Linux\s*[A-Za-z0-9. _-]{0,30}|CentOS\s*[A-Za-z0-9. _-]{0,30})/i);
    return match?.[1]?.trim() || '';
  }

  function classifyOs(value) {
    const text = String(value || '').toLowerCase();
    if (/(windows|microsoft|win 10|win 11)/i.test(text)) return 'windows';
    if (/(linux|ubuntu|debian|astra|centos|fedora)/i.test(text)) return 'linux';
    return 'unknown';
  }

  function normalizeLogin(value) {
    const normalized = String(value || '').trim().toLowerCase().replace(/\\/g, '/');
    return normalized.includes('/') ? normalized.split('/').at(-1) : normalized;
  }

  function parseHtml(html) {
    return new DOMParser().parseFromString(html, 'text/html');
  }

  function ensureSession(response, html) {
    let loginPage = false;
    try { loginPage = /login/i.test(new URL(response.url, location.origin).pathname); } catch (_) {}
    const head = String(html || '').slice(0, 120000);
    if (loginPage || /name=["']login_name["']/i.test(head) || /front\/login\.php/i.test(head)) {
      throw new SessionRequiredError('Сессия GLPI истекла. Войдите заново.');
    }
  }

  function getCsrf(doc) {
    const token = doc.querySelector('meta[property="glpi:csrf_token"]')?.content
      || doc.querySelector('input[name="_glpi_csrf_token"]')?.value;
    if (!token) throw new Error('GLPI: CSRF-токен не найден');
    return token;
  }

  function appendFormValue(params, key, value) {
    if (value === undefined || value === null) return;
    if (Array.isArray(value)) {
      value.forEach((item, index) => {
        if (item && typeof item === 'object') appendFormValue(params, `${key}[${index}]`, item);
        else params.append(`${key}[]`, String(item));
      });
      return;
    }
    if (typeof value === 'object') {
      Object.entries(value).forEach(([subKey, item]) => appendFormValue(params, `${key}[${subKey}]`, item));
      return;
    }
    params.append(key, typeof value === 'boolean' ? (value ? '1' : '0') : String(value));
  }

  function extractJsonObjectAfter(text, marker) {
    const markerIndex = text.indexOf(marker);
    const start = text.indexOf('{', markerIndex + marker.length);
    if (markerIndex < 0 || start < 0) return null;
    let depth = 0;
    let inString = false;
    let escaped = false;
    for (let index = start; index < text.length; index++) {
      const char = text[index];
      if (inString) {
        if (escaped) escaped = false;
        else if (char === '\\') escaped = true;
        else if (char === '"') inString = false;
        continue;
      }
      if (char === '"') { inString = true; continue; }
      if (char === '{') depth += 1;
      if (char === '}') depth -= 1;
      if (depth === 0) {
        try { return JSON.parse(text.slice(start, index + 1)); } catch (_) { return {}; }
      }
    }
    return {};
  }

  async function mapWithConcurrency(items, limit, worker) {
    const result = new Array(items.length);
    let next = 0;
    const runners = Array.from({ length: Math.min(limit, Math.max(1, items.length)) }, async () => {
      while (true) {
        const index = next++;
        if (index >= items.length) return;
        result[index] = await worker(items[index]);
      }
    });
    await Promise.all(runners);
    return result;
  }
})();
