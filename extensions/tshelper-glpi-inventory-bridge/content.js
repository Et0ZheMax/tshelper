'use strict';

(() => {
  const PARSER_VERSION = '0.1.2';
  const POLL_MS = 3000;
  const IDLE_POLL_MS = 5000;
  const REQUEST_TIMEOUT_MS = 7000;
  const RENDERED_EMPTY_READY_MS = 4000;
  const USER_VERIFY_CONCURRENCY = 5;
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
    sendResponse({ ready: Date.now() - renderedPageStartedAt > RENDERED_EMPTY_READY_MS, computers: [] });
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
      await reportProgress(job, 'Поиск пользователя', `Ищу точный login ${base.login}`);
      const user = await resolveExactUser(job);
      if (!user) {
        await reportProgress(job, 'Пользователь не найден', `Точный login ${base.login} не подтверждён`);
        return { ...base, status: 'not_found', resolution: 'exact-login' };
      }
      if (user.ambiguous) {
        await reportProgress(job, 'Неоднозначный результат', 'Найдено несколько User с одинаковым login');
        return { ...base, status: 'ambiguous', resolution: 'exact-login' };
      }

      await reportProgress(job, 'Чтение оборудования', `User #${user.id}: ${user.name || user.login}`);
      const rows = await loadUsedComputers(user.id);
      const actionableRows = rows.filter((item) => !isRemoteAccessHostname(item.name));
      if (!actionableRows.length) {
        const remoteCount = rows.length - actionableRows.length;
        const detail = remoteCount ? `; исключено удалённых lr-/wr-: ${remoteCount}` : '';
        await reportProgress(job, 'Оборудование не найдено', `User #${user.id}: нет рабочих Computer${detail}`);
        return {
          ...base,
          status: 'no_computers',
          resolution: 'exact-login',
          glpi_user_id: user.id,
          glpi_name: user.name || ''
        };
      }
      await reportProgress(job, 'Чтение карточек Computer', `Рабочих компьютеров: ${actionableRows.length}`);
      const computers = (await mapWithConcurrency(actionableRows, 3, enrichComputer))
        .filter((item) => !isRemoteAccessHostname(item.hostname));
      if (!computers.length) {
        await reportProgress(job, 'Оборудование не найдено', 'После чтения карточек остались только lr-/wr-');
        return {
          ...base,
          status: 'no_computers',
          resolution: 'exact-login',
          glpi_user_id: user.id,
          glpi_name: user.name || ''
        };
      }
      await reportProgress(job, 'Готово', computers.map((item) => item.hostname).filter(Boolean).join(', '));
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
      await reportProgress(job, sessionRequired ? 'Требуется вход в GLPI' : 'Ошибка', String(error?.message || error));
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
      await reportProgress(job, 'Проверка сохранённого User ID', `User #${knownId}`);
      const known = await fetchUserIdentity(knownId);
      if (normalizeLogin(known.login) === wanted) return known;
    }

    let candidates = [];
    try {
      candidates = await searchUsersViaHtml(wanted);
    } catch (error) {
      if (error instanceof SessionRequiredError) throw error;
      console.debug('[TSHelper Inventory] HTML-поиск User недоступен:', error);
      await reportProgress(job, 'Резервный AJAX-поиск', String(error?.message || error));
    }
    if (!candidates.length) {
      await reportProgress(job, 'Резервный AJAX-поиск', `HTML-поиск не нашёл login ${wanted}`);
    }
    try {
      if (!candidates.length) {
        const descriptor = await loadUserSearchDescriptor();
        candidates = await searchUsers(wanted, descriptor);
      }
    } catch (error) {
      if (error instanceof SessionRequiredError) throw error;
      console.debug('[TSHelper Inventory] Резервный AJAX-поиск User недоступен:', error);
      await reportProgress(job, 'Резервный поиск недоступен', String(error?.message || error));
    }
    await reportProgress(job, 'Проверка login кандидатов', `Кандидатов User: ${candidates.length}`);
    const checked = await mapWithConcurrency(candidates.slice(0, 25), USER_VERIFY_CONCURRENCY, async (candidate) => {
      try {
        const identity = await fetchUserIdentity(candidate.id);
        return normalizeLogin(identity.login) === wanted ? identity : null;
      } catch (error) {
        if (error instanceof SessionRequiredError) throw error;
        console.debug('[TSHelper Inventory] Не удалось проверить User', candidate.id, error);
        return null;
      }
    });
    const verified = checked.filter(Boolean);
    if (verified.length === 1) return verified[0];
    if (verified.length > 1) return { ambiguous: true };
    return null;
  }

  async function searchUsersViaHtml(query) {
    const urls = [
      `/front/user.php?is_deleted=0&as_map=0&browse=0&criteria[0][link]=AND&criteria[0][field]=1&criteria[0][searchtype]=contains&criteria[0][value]=${encodeURIComponent(query)}&search=Search`,
      `/front/search.php?globalsearch=${encodeURIComponent(query)}`
    ];
    const candidates = [];
    const seen = new Set();
    for (const url of urls) {
      const response = await fetchWithTimeout(url, {
        credentials: 'same-origin', cache: 'no-store', redirect: 'follow'
      });
      const html = await response.text();
      ensureSession(response, html);
      if (!response.ok) continue;
      const doc = parseHtml(html);
      for (const anchor of doc.querySelectorAll('a[href*="user.form.php"][href*="id="]')) {
        let id = 0;
        try { id = Number(new URL(anchor.href, location.origin).searchParams.get('id')) || 0; } catch (_) {}
        if (!id || seen.has(id)) continue;
        seen.add(id);
        candidates.push({
          id,
          name: String(anchor.textContent || '').replace(/\s+/g, ' ').trim(),
          source: 'html-search'
        });
      }
      if (candidates.length) break;
    }
    return candidates;
  }

  async function reportProgress(job, stage, message = '') {
    try {
      return await chrome.runtime.sendMessage({
        type: 'TSH_INVENTORY_REPORT_PROGRESS',
        payload: {
          job_id: job.id,
          login: normalizeLogin(job.login),
          stage: String(stage || 'Обработка'),
          message: String(message || ''),
          parser_version: PARSER_VERSION,
          updated_at: new Date().toISOString()
        }
      });
    } catch (_) {
      return null;
    }
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
    const response = await fetchWithTimeout('/front/ticket.form.php', {
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
    const response = await fetchWithTimeout('/ajax/actors.php', {
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
    const response = await fetchWithTimeout(userPageUrl, {
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
      const tabResponse = await fetchWithTimeout(new URL(tabUrl, location.origin), {
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
    const response = await fetchWithTimeout(`${path}?id=${encodeURIComponent(id)}&forcetab=${encodeURIComponent(`${itemtype}$main`)}`, {
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
        const tabResponse = await fetchWithTimeout(new URL(ajaxUrl, location.origin), {
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
        const response = await fetchWithTimeout(new URL(url, location.origin), {
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

  function isRemoteAccessHostname(value) {
    const shortName = String(value || '').trim().split('.', 1)[0].toLowerCase();
    return shortName.startsWith('lr-') || shortName.startsWith('wr-');
  }

  async function fetchWithTimeout(resource, options = {}, timeoutMs = REQUEST_TIMEOUT_MS) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetch(resource, { ...options, signal: controller.signal });
    } catch (error) {
      if (error?.name === 'AbortError') {
        throw new Error(`GLPI не ответил за ${Math.round(timeoutMs / 1000)} сек.`);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
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
