const state = {
  apiKey: localStorage.getItem("ag_api_key") || "",
  accounts: [],
  currentAccountId: null,
  mappings: {
    anthropic: {},
    openai: {},
    custom: {},
  },
  models: [],
  selectedProtocol: "openai",
  selectedModelId: null,
  oauth: {
    status: "idle",
    message: "",
    authUrl: "",
  },
};

const elements = {
  apiKeyInput: document.getElementById("apiKeyInput"),
  saveKeyBtn: document.getElementById("saveKeyBtn"),
  toggleKeyBtn: document.getElementById("toggleKeyBtn"),
  summaryGrid: document.getElementById("summaryGrid"),
  currentAccountBadge: document.getElementById("currentAccountBadge"),
  currentAccountBody: document.getElementById("currentAccountBody"),
  accountsList: document.getElementById("accountsList"),
  refreshAllBtn: document.getElementById("refreshAllBtn"),
  refreshTokenInput: document.getElementById("refreshTokenInput"),
  addAccountBtn: document.getElementById("addAccountBtn"),
  toast: document.getElementById("toast"),
  oauthStartBtn: document.getElementById("oauthStartBtn"),
  oauthLinkBox: document.getElementById("oauthLinkBox"),
  oauthLinkText: document.getElementById("oauthLinkText"),
  oauthOpenBtn: document.getElementById("oauthOpenBtn"),
  oauthCopyBtn: document.getElementById("oauthCopyBtn"),
  oauthStatus: document.getElementById("oauthStatus"),
  oauthFallbackBox: document.getElementById("oauthFallbackBox"),
  oauthCallbackInput: document.getElementById("oauthCallbackInput"),
  oauthCallbackSubmit: document.getElementById("oauthCallbackSubmit"),
  resetMappingBtn: document.getElementById("resetMappingBtn"),
  customMappingSource: document.getElementById("customMappingSource"),
  customMappingTarget: document.getElementById("customMappingTarget"),
  addCustomMappingBtn: document.getElementById("addCustomMappingBtn"),
  customMappingList: document.getElementById("customMappingList"),
  protocolGrid: document.getElementById("protocolGrid"),
  modelList: document.getElementById("modelList"),
  codeSample: document.getElementById("codeSample"),
  protocolBadge: document.getElementById("protocolBadge"),
  copyExampleBtn: document.getElementById("copyExampleBtn"),
};

const defaultMappings = {
  anthropic: {
    "claude-4.5-series": "gemini-3-pro-high",
    "claude-3.5-series": "claude-sonnet-4-5-thinking",
  },
  openai: {
    "gpt-4-series": "gemini-3-pro-high",
    "gpt-4o-series": "gemini-3-flash",
    "gpt-5-series": "gemini-3-flash",
  },
};

const protocolBadges = {
  openai: "OpenAI SDK",
  anthropic: "Anthropic SDK",
  gemini: "Google GenAI",
};

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add("show");
  setTimeout(() => elements.toast.classList.remove("show"), 2400);
}

function getBaseUrl() {
  const { protocol, hostname, port } = window.location;
  return `${protocol}//${hostname}${port ? `:${port}` : ""}`;
}

function getOpenAiBaseUrl() {
  return `${getBaseUrl()}/v1`;
}

function buildModelOptions(models) {
  if (!models.length) {
    return '<option value="">Loading models...</option>';
  }
  return models
    .map((model) => `<option value="${escapeHtml(model)}">${escapeHtml(model)}</option>`)
    .join("");
}

function copyText(text, label) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    showToast(label);
  });
}

let oauthPollTimer = null;

function updateOAuthUI(status, message, authUrl) {
  state.oauth.status = status || "idle";
  state.oauth.message = message || "";
  if (typeof authUrl === "string") {
    state.oauth.authUrl = authUrl;
  }
  const isLoading = state.oauth.status === "loading";
  const isWaiting = state.oauth.status === "waiting";
  const isBusy = isLoading || isWaiting;

  if (elements.oauthStatus) {
    elements.oauthStatus.textContent = state.oauth.message || "";
    elements.oauthStatus.classList.remove("success", "error");
    if (state.oauth.status === "success") {
      elements.oauthStatus.classList.add("success");
    }
    if (state.oauth.status === "error") {
      elements.oauthStatus.classList.add("error");
    }
  }

  if (elements.oauthStartBtn) {
    elements.oauthStartBtn.disabled = isBusy;
    elements.oauthStartBtn.textContent = isBusy ? "Waiting for OAuth..." : "Start OAuth Login";
  }

  if (elements.oauthLinkBox) {
    if (state.oauth.authUrl) {
      elements.oauthLinkBox.classList.remove("hidden");
    } else {
      elements.oauthLinkBox.classList.add("hidden");
    }
  }

  if (elements.oauthLinkText && state.oauth.authUrl) {
    elements.oauthLinkText.textContent = state.oauth.authUrl;
  }

  if (elements.oauthOpenBtn) {
    elements.oauthOpenBtn.disabled = !state.oauth.authUrl;
  }

  if (elements.oauthCallbackSubmit) {
    elements.oauthCallbackSubmit.disabled = isLoading;
  }
}

async function fetchOAuthStatus() {
  if (!elements.oauthStatus) return;
  try {
    const data = await apiFetch("/api/oauth/status");
    if (!data) return;
    updateOAuthUI(data.status, data.message || "", data.auth_url || "");
    if (data.status === "success") {
      stopOAuthPolling();
      showToast("OAuth success");
      loadAccounts();
    } else if (data.status === "waiting") {
      startOAuthPolling();
    } else if (data.status === "error") {
      stopOAuthPolling();
    }
  } catch (err) {
    stopOAuthPolling();
    updateOAuthUI("error", `OAuth status failed: ${err.message}`);
  }
}

function startOAuthPolling() {
  if (oauthPollTimer) {
    return;
  }
  oauthPollTimer = setInterval(fetchOAuthStatus, 2000);
}

function stopOAuthPolling() {
  if (oauthPollTimer) {
    clearInterval(oauthPollTimer);
    oauthPollTimer = null;
  }
}

function openOAuthLink() {
  if (!state.oauth.authUrl) return;
  window.open(state.oauth.authUrl, "_blank", "noopener");
}

async function startOAuthLogin() {
  if (!elements.oauthStartBtn) return;
  updateOAuthUI("loading", "Preparing OAuth link...");
  try {
    const data = await apiFetch("/api/oauth/prepare");
    if (!data || !data.auth_url) {
      throw new Error("OAuth URL missing");
    }
    updateOAuthUI("waiting", "Waiting for authorization...", data.auth_url);
    if (elements.oauthCallbackInput) {
      elements.oauthCallbackInput.value = "";
    }
    openOAuthLink();
    startOAuthPolling();
    fetchOAuthStatus();
  } catch (err) {
    updateOAuthUI("error", err.message || "OAuth failed");
  }
}

async function submitOAuthCallback() {
  if (!elements.oauthCallbackInput) return;
  const callbackUrl = elements.oauthCallbackInput.value.trim();
  if (!callbackUrl) {
    updateOAuthUI("error", "Please paste the callback URL first.");
    return;
  }
  updateOAuthUI("loading", "Submitting callback URL...");
  try {
    const data = await apiFetch("/api/oauth/callback", {
      method: "POST",
      body: JSON.stringify({ callback_url: callbackUrl }),
    });
    updateOAuthUI(data.status || "success", data.message || "", data.auth_url || "");
    stopOAuthPolling();
    if (data.status === "success") {
      showToast("OAuth success");
      elements.oauthCallbackInput.value = "";
      loadAccounts();
    }
  } catch (err) {
    stopOAuthPolling();
    updateOAuthUI("error", err.message || "OAuth callback failed");
  }
}

function setApiKey(key) {
  state.apiKey = key.trim();
  localStorage.setItem("ag_api_key", state.apiKey);
  elements.apiKeyInput.value = state.apiKey;
}

async function apiFetch(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  if (options.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  if (state.apiKey) {
    headers["x-api-key"] = state.apiKey;
  }

  const response = await fetch(path, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const text = await response.text();
    let message = text || response.statusText;
    try {
      const parsed = JSON.parse(text);
      if (parsed && parsed.error) {
        message = parsed.error;
      }
    } catch (_) {}
    throw new Error(message);
  }

  if (response.status === 204) {
    return null;
  }
  return response.json();
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatDate(timestamp) {
  if (!timestamp) return "-";
  const date = new Date(timestamp * 1000);
  return date.toLocaleString();
}

function computeSummary(accounts) {
  const total = accounts.length;
  let geminiAvg = 0;
  let claudeAvg = 0;
  let geminiCount = 0;
  let claudeCount = 0;

  accounts.forEach((account) => {
    const models = (account.quota && account.quota.models) || [];
    models.forEach((model) => {
      if (model.name.includes("gemini")) {
        geminiAvg += model.percentage || 0;
        geminiCount += 1;
      }
      if (model.name.includes("claude")) {
        claudeAvg += model.percentage || 0;
        claudeCount += 1;
      }
    });
  });

  const avgGemini = geminiCount ? Math.round(geminiAvg / geminiCount) : 0;
  const avgClaude = claudeCount ? Math.round(claudeAvg / claudeCount) : 0;

  return { total, avgGemini, avgClaude };
}

function computeAccountStats(account) {
  const models = (account.quota && account.quota.models) || [];
  let geminiTotal = 0;
  let claudeTotal = 0;
  let geminiCount = 0;
  let claudeCount = 0;

  models.forEach((model) => {
    const name = String(model.name || "").toLowerCase();
    if (name.includes("gemini")) {
      geminiTotal += model.percentage || 0;
      geminiCount += 1;
    }
    if (name.includes("claude")) {
      claudeTotal += model.percentage || 0;
      claudeCount += 1;
    }
  });

  return {
    geminiAvg: geminiCount ? Math.round(geminiTotal / geminiCount) : 0,
    claudeAvg: claudeCount ? Math.round(claudeTotal / claudeCount) : 0,
    geminiCount,
    claudeCount,
  };
}

function renderMetricCard(label, value, count) {
  const safeValue = Math.max(0, Math.min(100, value || 0));
  return `
    <div class="metric-card">
      <span class="metric-title">${escapeHtml(label)}</span>
      <strong>${safeValue}%</strong>
      <div class="progress"><div style="width:${safeValue}%"></div></div>
      <span class="metric-meta">${count || 0} models</span>
    </div>
  `;
}

function renderTierBadge(tier) {
  if (!tier || tier === "-") {
    return '<span class="badge">Tier: -</span>';
  }
  if (String(tier).toLowerCase().includes("pro")) {
    return '<span class="badge pro">PRO</span>';
  }
  return `<span class="badge">Tier: ${escapeHtml(tier)}</span>`;
}

function renderSummary() {
  const summary = computeSummary(state.accounts);
  const cards = [
    { title: "Gemini Avg", value: `${summary.avgGemini}%` },
    { title: "Claude Avg", value: `${summary.avgClaude}%` },
  ];

  elements.summaryGrid.innerHTML = cards
    .map(
      (card, index) => `
      <div class="summary-card" style="animation-delay:${index * 0.05}s">
        <h3>${escapeHtml(card.title)}</h3>
        <div class="value">${escapeHtml(card.value)}</div>
      </div>
    `
    )
    .join("");
}

function renderCurrentAccount() {
  const current = state.accounts.find((a) => a.id === state.currentAccountId);
  if (!current) {
    elements.currentAccountBadge.textContent = "None";
    elements.currentAccountBody.innerHTML = "<div class=\"empty\">No account selected.</div>";
    return;
  }

  elements.currentAccountBadge.textContent = current.email || "Account";
  const stats = computeAccountStats(current);
  elements.currentAccountBody.innerHTML = `
    <div class="card-title">
      <strong>${escapeHtml(current.email)}</strong>
      <span class="muted">${escapeHtml(current.name || "Unnamed")}</span>
    </div>
    <div class="badges">
      ${current.quota && current.quota.subscription_tier ? renderTierBadge(current.quota.subscription_tier) : ""}
      ${current.disabled ? '<span class="badge danger">Disabled</span>' : '<span class="badge success">Active</span>'}
    </div>
    <div class="account-metrics">
      ${renderMetricCard("Gemini Avg", stats.geminiAvg, stats.geminiCount)}
      ${renderMetricCard("Claude Avg", stats.claudeAvg, stats.claudeCount)}
    </div>
  `;
}

function renderAccounts() {
  if (!state.accounts.length) {
    elements.accountsList.innerHTML = '<div class="empty">No accounts found.</div>';
    return;
  }

  elements.accountsList.innerHTML = state.accounts
    .map((account) => {
      const isCurrent = account.id === state.currentAccountId;
      const tier = account.quota && account.quota.subscription_tier ? account.quota.subscription_tier : "-";
      const stats = computeAccountStats(account);
      return `
        <div class="table-row">
          <div class="table-cell">
            <strong>${escapeHtml(account.email)}</strong>
            <span class="muted">${escapeHtml(account.name || "Unnamed")}</span>
          </div>
          <div class="table-cell">
            ${isCurrent ? '<span class="badge success">Current</span>' : ""}
            ${account.disabled ? '<span class="badge danger">Disabled</span>' : '<span class="badge success">Active</span>'}
          </div>
          <div class="table-cell">
            ${renderTierBadge(tier)}
          </div>
          <div class="table-cell">
            <span class="badge">${stats.geminiAvg}%</span>
          </div>
          <div class="table-cell">
            <span class="badge">${stats.claudeAvg}%</span>
          </div>
          <div class="table-cell table-actions">
            <button class="secondary" data-action="set-current" data-id="${escapeHtml(account.id)}">Set Current</button>
            <button class="ghost" data-action="refresh-quota" data-id="${escapeHtml(account.id)}">Refresh</button>
            <button class="danger" data-action="delete" data-id="${escapeHtml(account.id)}">Delete</button>
          </div>
        </div>
      `;
    })
    .join("");
}

function normalizeMappings(payload) {
  const anthropic = Object.assign({}, defaultMappings.anthropic, payload.anthropic_mapping || {});
  const openai = Object.assign({}, defaultMappings.openai, payload.openai_mapping || {});
  const custom = Object.assign({}, payload.custom_mapping || {});
  return { anthropic, openai, custom };
}

function renderMappingOptions() {
  const options = buildModelOptions(state.models);
  const selects = document.querySelectorAll(".router-select");
  selects.forEach((select) => {
    const scope = select.dataset.mappingScope;
    const key = select.dataset.mappingKey;
    if (!scope || !key) return;
    select.innerHTML = options;
    const value = state.mappings[scope][key] || "";
    if (value) {
      select.value = value;
    }
  });

  if (elements.customMappingTarget) {
    elements.customMappingTarget.innerHTML = options;
  }
}

function renderCustomMappingList() {
  if (!elements.customMappingList) return;
  const entries = Object.entries(state.mappings.custom || {});
  if (!entries.length) {
    elements.customMappingList.innerHTML = '<div class="empty">No custom mappings yet.</div>';
    return;
  }
  elements.customMappingList.innerHTML = entries
    .map(
      ([source, target]) => `
      <div class="mapping-row">
        <code>${escapeHtml(source)}</code>
        <code>${escapeHtml(target)}</code>
        <button class="ghost small" data-remove-mapping="${escapeHtml(source)}" type="button">Remove</button>
      </div>
    `
    )
    .join("");
}

function renderProtocolCards() {
  if (!elements.protocolGrid) return;
  elements.protocolGrid.querySelectorAll(".protocol-card").forEach((card) => {
    const protocol = card.dataset.protocol;
    card.classList.toggle("active", protocol === state.selectedProtocol);
  });
  if (elements.protocolBadge) {
    elements.protocolBadge.textContent = protocolBadges[state.selectedProtocol] || "SDK";
  }
}

function renderModelList() {
  if (!elements.modelList) return;
  if (!state.models.length) {
    elements.modelList.innerHTML = '<div class="empty">No models loaded yet.</div>';
    return;
  }

  if (!state.selectedModelId) {
    state.selectedModelId = state.models[0];
  }

  elements.modelList.innerHTML = state.models
    .map((model) => {
      const isActive = model === state.selectedModelId;
      return `
        <div class="model-row ${isActive ? "active" : ""}" data-model-id="${escapeHtml(model)}">
          <code>${escapeHtml(model)}</code>
          <button class="ghost small" data-copy-model="${escapeHtml(model)}" type="button">Copy</button>
        </div>
      `;
    })
    .join("");
}

function getExampleCode(modelId) {
  const apiKey = state.apiKey || "YOUR_API_KEY";
  const baseUrl = getBaseUrl();
  const openaiBase = getOpenAiBaseUrl();

  if (state.selectedProtocol === "anthropic") {
    return `from anthropic import Anthropic

client = Anthropic(
    base_url="${baseUrl}",
    api_key="${apiKey}"
)

response = client.messages.create(
    model="${modelId}",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}]
)

print(response.content[0].text)`;
  }

  if (state.selectedProtocol === "gemini") {
    return `# pip install google-generativeai
import google.generativeai as genai

genai.configure(
    api_key="${apiKey}",
    transport="rest",
    client_options={"api_endpoint": "${baseUrl}"}
)

model = genai.GenerativeModel("${modelId}")
response = model.generate_content("Hello")
print(response.text)`;
  }

  if (modelId && modelId.startsWith("gemini-3-pro-image")) {
    return `from openai import OpenAI

client = OpenAI(
    base_url="${openaiBase}",
    api_key="${apiKey}"
)

response = client.images.generate(
    model="${modelId}",
    prompt="Draw a futuristic city",
    size="1024x1024"
)

print(response.data[0].b64_json)`;
  }

  return `from openai import OpenAI

client = OpenAI(
    base_url="${openaiBase}",
    api_key="${apiKey}"
)

response = client.chat.completions.create(
    model="${modelId}",
    messages=[{"role": "user", "content": "Hello"}]
)

print(response.choices[0].message.content)`;
}

function renderExampleCode() {
  if (!elements.codeSample) return;
  const modelId = state.selectedModelId || "gemini-3-pro-high";
  elements.codeSample.textContent = getExampleCode(modelId);
}

function setActiveTab(tabId) {
  const requested = tabId || "overview";
  const targetTab = document.getElementById(requested) ? requested : "overview";
  document.querySelectorAll(".tab-page").forEach((page) => {
    page.classList.toggle("active", page.id === targetTab);
  });
  document.querySelectorAll(".nav-link[data-tab]").forEach((link) => {
    link.classList.toggle("active", link.dataset.tab === targetTab);
  });
  const nextHash = `#${targetTab}`;
  if (window.location.hash !== nextHash) {
    history.replaceState(null, "", nextHash);
  }
}

function initTabs() {
  const hash = window.location.hash.replace("#", "");
  setActiveTab(hash || "overview");
}

async function loadAccounts() {
  try {
    const data = await apiFetch("/api/accounts");
    state.accounts = data.accounts || [];
    state.currentAccountId = data.current_account_id || null;
    renderSummary();
    renderCurrentAccount();
    renderAccounts();
  } catch (err) {
    showToast(`Load failed: ${err.message}`);
  }
}

async function loadMappings() {
  try {
    const data = await apiFetch("/api/proxy/mappings");
    state.mappings = normalizeMappings(data || {});
    renderMappingOptions();
    renderCustomMappingList();
  } catch (err) {
    state.mappings = {
      anthropic: Object.assign({}, defaultMappings.anthropic),
      openai: Object.assign({}, defaultMappings.openai),
      custom: {},
    };
    renderMappingOptions();
    renderCustomMappingList();
    showToast(`Mapping load failed: ${err.message}`);
  }
}

async function saveMappings() {
  await apiFetch("/api/proxy/mappings", {
    method: "PUT",
    body: JSON.stringify({
      anthropic_mapping: state.mappings.anthropic,
      openai_mapping: state.mappings.openai,
      custom_mapping: state.mappings.custom,
    }),
  });
}

async function handleResetMappings() {
  state.mappings = {
    anthropic: Object.assign({}, defaultMappings.anthropic),
    openai: Object.assign({}, defaultMappings.openai),
    custom: {},
  };
  renderMappingOptions();
  renderCustomMappingList();
  try {
    await saveMappings();
    showToast("Mappings reset");
  } catch (err) {
    showToast(`Reset failed: ${err.message}`);
  }
}

async function loadModels() {
  try {
    const data = await apiFetch("/v1/models");
    const models = (data && data.data ? data.data.map((item) => item.id) : []).filter(Boolean);
    models.sort();
    state.models = models;
    renderMappingOptions();
    renderModelList();
    renderExampleCode();
  } catch (err) {
    showToast(`Models load failed: ${err.message}`);
  }
}

async function updateGroupMapping(scope, key, value) {
  if (!scope || !key || !value) return;
  state.mappings[scope][key] = value;
  try {
    await saveMappings();
    showToast("Mapping updated");
  } catch (err) {
    showToast(`Update failed: ${err.message}`);
  }
}

async function addCustomMapping() {
  const source = elements.customMappingSource.value.trim();
  const target = elements.customMappingTarget.value;
  if (!source) {
    showToast("Original model id is required");
    return;
  }
  if (!target) {
    showToast("Select a target model");
    return;
  }
  state.mappings.custom[source] = target;
  renderCustomMappingList();
  try {
    await saveMappings();
    elements.customMappingSource.value = "";
    showToast("Custom mapping added");
  } catch (err) {
    showToast(`Save failed: ${err.message}`);
  }
}

async function removeCustomMapping(key) {
  if (!key || !state.mappings.custom[key]) return;
  delete state.mappings.custom[key];
  renderCustomMappingList();
  try {
    await saveMappings();
    showToast("Custom mapping removed");
  } catch (err) {
    showToast(`Remove failed: ${err.message}`);
  }
}

function refreshProtocolCopyTargets() {
  const baseUrl = getBaseUrl();
  const openaiBase = getOpenAiBaseUrl();

  const copyMap = {
    "openai-base": openaiBase,
    "anthropic-base": `${baseUrl}/v1/messages`,
    "gemini-base": `${baseUrl}/v1beta/models`,
  };

  Object.entries(copyMap).forEach(([key, value]) => {
    const button = elements.protocolGrid && elements.protocolGrid.querySelector(`[data-copy="${key}"]`);
    if (button) {
      button.dataset.copyValue = value;
    }
  });
}

async function handleAddAccount() {
  const token = elements.refreshTokenInput.value.trim();
  if (!token) {
    showToast("Refresh token is required");
    return;
  }
  elements.addAccountBtn.disabled = true;
  try {
    await apiFetch("/api/accounts", {
      method: "POST",
      body: JSON.stringify({ refresh_token: token }),
    });
    elements.refreshTokenInput.value = "";
    showToast("Account added");
    await loadAccounts();
  } catch (err) {
    showToast(`Add failed: ${err.message}`);
  } finally {
    elements.addAccountBtn.disabled = false;
  }
}

async function handleSetCurrent(accountId) {
  try {
    await apiFetch("/api/accounts/current", {
      method: "PUT",
      body: JSON.stringify({ account_id: accountId }),
    });
    showToast("Current account updated");
    await loadAccounts();
  } catch (err) {
    showToast(`Update failed: ${err.message}`);
  }
}

async function handleDelete(accountId) {
  if (!window.confirm("Delete this account?")) {
    return;
  }
  try {
    await apiFetch(`/api/accounts/${accountId}`, { method: "DELETE" });
    showToast("Account deleted");
    await loadAccounts();
  } catch (err) {
    showToast(`Delete failed: ${err.message}`);
  }
}

async function handleRefreshQuota(accountId) {
  try {
    await apiFetch(`/api/accounts/${accountId}/refresh_quota`, { method: "POST" });
    showToast("Quota refreshed");
    await loadAccounts();
  } catch (err) {
    showToast(`Refresh failed: ${err.message}`);
  }
}

async function handleRefreshAll() {
  elements.refreshAllBtn.disabled = true;
  try {
    await apiFetch("/api/accounts/refresh_quotas", { method: "POST" });
    showToast("All quotas refreshed");
    await loadAccounts();
  } catch (err) {
    showToast(`Refresh failed: ${err.message}`);
  } finally {
    elements.refreshAllBtn.disabled = false;
  }
}

function bindEvents() {
  elements.apiKeyInput.value = state.apiKey;

  elements.saveKeyBtn.addEventListener("click", () => {
    setApiKey(elements.apiKeyInput.value);
    showToast("API key saved");
    loadAccounts();
    loadMappings();
    loadModels();
    renderExampleCode();
  });

  elements.toggleKeyBtn.addEventListener("click", () => {
    const isPassword = elements.apiKeyInput.type === "password";
    elements.apiKeyInput.type = isPassword ? "text" : "password";
    elements.toggleKeyBtn.textContent = isPassword ? "Hide" : "Show";
  });

  elements.refreshAllBtn.addEventListener("click", handleRefreshAll);
  elements.addAccountBtn.addEventListener("click", handleAddAccount);
  if (elements.oauthStartBtn) {
    elements.oauthStartBtn.addEventListener("click", startOAuthLogin);
  }
  if (elements.oauthOpenBtn) {
    elements.oauthOpenBtn.addEventListener("click", openOAuthLink);
  }
  if (elements.oauthCopyBtn) {
    elements.oauthCopyBtn.addEventListener("click", () => {
      copyText(state.oauth.authUrl, "OAuth link copied");
    });
  }
  if (elements.oauthCallbackSubmit) {
    elements.oauthCallbackSubmit.addEventListener("click", submitOAuthCallback);
  }
  if (elements.oauthCallbackInput) {
    elements.oauthCallbackInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        submitOAuthCallback();
      }
    });
  }
  if (elements.resetMappingBtn) {
    elements.resetMappingBtn.addEventListener("click", handleResetMappings);
  }
  if (elements.addCustomMappingBtn) {
    elements.addCustomMappingBtn.addEventListener("click", addCustomMapping);
  }
  if (elements.copyExampleBtn) {
    elements.copyExampleBtn.addEventListener("click", () => {
      copyText(elements.codeSample.textContent || "", "Example copied");
    });
  }

  document.addEventListener("click", (event) => {
    const target = event.target.closest("button[data-action]");
    if (!target) return;
    const action = target.dataset.action;
    const accountId = target.dataset.id;
    if (!accountId) return;

    if (action === "set-current") {
      handleSetCurrent(accountId);
    } else if (action === "refresh-quota") {
      handleRefreshQuota(accountId);
    } else if (action === "delete") {
      handleDelete(accountId);
    }
  });

  document.addEventListener("change", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLSelectElement)) return;
    if (!target.classList.contains("router-select")) return;
    updateGroupMapping(target.dataset.mappingScope, target.dataset.mappingKey, target.value);
  });

  document.addEventListener("click", (event) => {
    const navButton = event.target.closest(".nav-link[data-tab]");
    if (navButton) {
      setActiveTab(navButton.dataset.tab);
      return;
    }

    const removeBtn = event.target.closest("button[data-remove-mapping]");
    if (removeBtn) {
      removeCustomMapping(removeBtn.dataset.removeMapping);
      return;
    }

    const copyButton = event.target.closest("button[data-copy]");
    if (copyButton) {
      const value = copyButton.dataset.copyValue;
      copyText(value, "Copied");
      return;
    }

    const copyModel = event.target.closest("button[data-copy-model]");
    if (copyModel) {
      const model = copyModel.dataset.copyModel;
      copyText(model, "Model copied");
      return;
    }

    const endpoint = event.target.closest("code[data-endpoint]");
    if (endpoint) {
      const path = endpoint.textContent.trim();
      const url = path.startsWith("/") ? `${getBaseUrl()}${path}` : `${getBaseUrl()}/${path}`;
      copyText(url, "Endpoint copied");
      return;
    }

    const protocolCard = event.target.closest(".protocol-card");
    if (protocolCard && protocolCard.dataset.protocol) {
      state.selectedProtocol = protocolCard.dataset.protocol;
      renderProtocolCards();
      renderExampleCode();
      return;
    }

    const modelRow = event.target.closest(".model-row");
    if (modelRow && modelRow.dataset.modelId) {
      state.selectedModelId = modelRow.dataset.modelId;
      renderModelList();
      renderExampleCode();
    }
  });
}

bindEvents();
initTabs();
refreshProtocolCopyTargets();
renderProtocolCards();
renderExampleCode();
loadAccounts();
loadMappings();
loadModels();
fetchOAuthStatus();
