/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 面板入口。boot 解析、视图路由、轮询调度(带抖动与可见性暂停)、失败退避、
 *             主题切换, 以及把四视图的行内操作接到 /panel/api/*。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 * @see       https://github.com/  完整版权与许可信息见仓库根目录 LICENSE
 */

import { BOOT, PREFIX, get, write, abortAll } from './api.js';
import {
  L, safe, renderSummary, renderMirrors, renderDecisions, renderCache,
  renderMe, renderTokens, renderConfig, renderTokenIssued,
} from './views.js';
import { fmtNum, inum } from './chart.js';

const VIEWS = ['summary', 'mirrors', 'decisions', 'cache'];
const ENDPOINT = {
  summary: '/api/summary',
  mirrors: '/api/mirrors',
  decisions: '/api/decisions',
  cache: '/api/cache',
  me: '/api/me',
  tokens: '/api/tokens',
  config: '/api/config',
};
const HOST = { me: '#admin-me', tokens: '#admin-tokens', config: '#admin-config' };

const st = {
  view: VIEWS.indexOf(BOOT.view) >= 0 ? BOOT.view : 'summary',
  factor: 1,
  fails: 0,
  backoffUntil: 0,
  timer: 0,
  busy: false,
  theme: 'auto',
  seen: {},
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function viewRoot(name) {
  return $(`#v-${name}`);
}

// ------------------------------------------------------------------
// 顶栏与状态
// ------------------------------------------------------------------

function setBanner(show, text) {
  const b = $('#link-down');
  if (!b) return;
  b.hidden = !show;
  if (text) b.textContent = text;
}

function setNotice(text) {
  const n = $('#notice');
  if (!n) return;
  n.hidden = !text;
  n.textContent = text || '';
  if (text) setTimeout(() => { n.hidden = true; }, 9000);
}

function replaceCode(host, prefixText, codeText) {
  host.textContent = '';
  host.appendChild(document.createTextNode(prefixText));
  const c = document.createElement('code');
  c.textContent = safe(codeText, 40);
  host.appendChild(c);
}

function updateTopMeta(meta) {
  if (!meta) return;
  if (meta.snapshot_version) replaceCode($('#meta-version'), 'snapshot ', meta.snapshot_version);
  const gen = $('#meta-generated');
  if (gen && meta.generated_at) {
    replaceCode(gen, '生成 ', new Date(Number(meta.generated_at) * 1000).toLocaleTimeString('zh-CN', { hour12: false }));
  }
  const foot = $('#foot-meta');
  if (foot) {
    foot.textContent = `视图 ${L.title[st.view]} · 轮询 ${Math.round(currentInterval() / 1000)}s · 前缀 ${safe(PREFIX, 40)}`;
  }
}

function currentInterval() {
  const base = Number((BOOT.poll_ms || {})[st.view] || 8000);
  // ±20% 抖动: 多个页签或多个部署同时开着面板时, 固定周期会让请求撞在同一毫秒,
  // 一次抽干 panel 桶的令牌, 症状是"面板时好时坏"却查不到原因。
  const jitter = 1 + (Math.random() * 0.4 - 0.2);
  const f = st.factor > 0 ? jitter / st.factor : 1;
  return Math.max(1500, Math.round(base * f));
}

// ------------------------------------------------------------------
// 轮询
// ------------------------------------------------------------------

/**
 * 拉一个视图的数据并渲染。
 *
 * 同类请求只允许一个在飞(api.js 里按 key 做 AbortController), 而这里再叠一层 busy:
 * 退避与可见性暂停管的是"什么时候再来", busy 管的是"这一次还没走完"。
 */
async function fetchView(view, params) {
  if (st.busy) return null;
  st.busy = true;
  let payload = null;
  try {
    payload = await get(ENDPOINT[view], params, `view:${view}`);
  } finally {
    st.busy = false;
  }
  if (!payload) return null;

  if (payload.error && payload.error.code === 'aborted') {
    // 被同类请求挤掉或超时取消的不算失败, 否则快速切视图会把自己逼进退避。
    return null;
  }
  if (!payload.ok) {
    st.fails += 1;
    if (st.fails >= 3) {
      st.backoffUntil = Date.now() + 30000;
      setBanner(true, `${L.banner.down}：连续 ${st.fails} 次失败（${safe(payload.error && payload.error.message, 60)}），已退避到 30s。`);
    } else {
      setNotice(`接口返回 ${safe(payload.error && payload.error.code, 40)}，第 ${st.fails} 次`);
    }
    return payload;
  }

  st.fails = 0;
  setBanner(false);
  paint(view, payload);
  updateTopMeta(payload.meta);
  return payload;
}

function paint(view, payload) {
  const root = viewRoot(view);
  if (!root) return;
  // 记住最近一次成功载荷: "新增还是编辑"这类判定要看当前榜单, 不该为此再发一次 GET。
  act.remember(view, payload);
  try {
    if (view === 'summary') renderSummary(root, payload, act);
    else if (view === 'mirrors') renderMirrors(root, payload, act);
    else if (view === 'decisions') renderDecisions(root, payload, act);
    else if (view === 'cache') renderCache(root, payload, act);
    root.dataset.loaded = '1';
  } catch (e) {
    root.textContent = '';
    const p = document.createElement('p');
    p.className = 'warnline';
    p.textContent = `渲染失败: ${safe(e && e.message, 200)}`;
    root.appendChild(p);
  }
}

function tick() {
  clearTimeout(st.timer);
  if (document.visibilityState !== 'visible' || st.factor === 0) {
    return;
  }
  if (Date.now() < st.backoffUntil) {
    st.timer = setTimeout(tick, Math.max(1000, st.backoffUntil - Date.now()));
    return;
  }
  fetchView(st.view).then(() => {
    st.timer = setTimeout(tick, currentInterval());
  });
}

function switchView(name, push) {
  const target = VIEWS.indexOf(name) >= 0 ? name : 'summary';
  st.view = target;
  st.fails = 0;
  st.backoffUntil = 0;
  setBanner(false);
  $$('.tab').forEach((t) => t.classList.toggle('on', t.dataset.view === target));
  $$('.view').forEach((v) => v.classList.toggle('on', v.dataset.view === target));
  if (push !== false) {
    history.replaceState(null, '', `${location.pathname}#${target}`);
  }
  fetchView(target);
}

// ------------------------------------------------------------------
// 操作
// ------------------------------------------------------------------

function adminHost(name) {
  const sel = HOST[name];
  return sel ? $(sel) : null;
}

/** 概览底部的管理块: 只在展开时取数据, 成功后标记, 免得每次展开都重复打接口。 */
function loadAdmin(name, host) {
  const target = host || adminHost(name);
  if (!target) return;
  get(ENDPOINT[name], null, `admin:${name}`).then((p) => {
    if (!p.ok) {
      target.textContent = '';
      const e = document.createElement('p');
      e.className = 'warnline';
      e.textContent = `加载失败: ${safe(p.error && p.error.message, 120)}`;
      target.appendChild(e);
      return;
    }
    target.dataset.loaded = '1';
    if (name === 'me') renderMe(target, p, act);
    else if (name === 'tokens') renderTokens(target, p, act);
    else renderConfig(target, p, act);
  });
}

const act = {
  load: loadAdmin,

  mirrorAction(id, action, extra, needsConfirm) {
    const body = { action, ...(extra || {}) };
    if (needsConfirm) body.confirm = true;
    write('POST', `/api/mirrors/${encodeURIComponent(id)}/action`, body, { key: `w:mirror:${id}:${action}` }).then((p) => {
      if (!p.ok) {
        setNotice(`操作失败: ${safe(p.error && p.error.message, 120)}`);
        return;
      }
      if (action === 'probe') setNotice(L.hints.probeQueued);
      if (action === 'reset_breaker') {
        const c = (p.data || {}).compaction || {};
        setNotice(c.locked
          ? '熔断复位已入队: 压实锁被占用, 下一次压实时生效(面板没有替你改状态)。'
          : `熔断已复位, 压实回读 obs=${inum(c.obs)} sources=${inum(c.sources)}。`);
      }
      fetchView('mirrors');
    });
  },

  setPriority(id, p) {
    if (!(p >= 1 && p <= 100)) {
      setNotice('priority 需在 1-100');
      return;
    }
    act.mirrorAction(id, 'priority', { priority: p });
  },

  deleteMirror(id) {
    write('DELETE', `/api/mirrors/${encodeURIComponent(id)}`, {}, { confirm: true, key: `w:del:${id}` }).then((p) => {
      setNotice(p.ok ? `已删除 ${safe(id, 40)}, 源池剩 ${inum(p.data && p.data.remaining)} 个`
        : `删除失败: ${safe(p.error && p.error.message, 120)}`);
      if (p.ok) fetchView('mirrors');
    });
  },

  saveMirror(body, out) {
    const rows = ((st.seen.mirrors || {}).data || {}).rows || [];
    const exists = rows.some((r) => r.id === body.id);
    const method = exists ? 'PUT' : 'POST';
    const path = exists ? `/api/mirrors/${encodeURIComponent(body.id)}` : '/api/mirrors';
    write(method, path, body, { key: `w:save:${body.id}` }).then((p) => {
      out.textContent = p.ok
        ? `已写入 overlay(${method}) ${safe((p.data || {}).row && (p.data || {}).row.id, 40)}; 回读 ${Object.keys((p.data || {}).row || {}).length} 个字段`
        : `失败: ${safe(p.error && p.error.message, 160)}`;
      const w = (p.data || {}).repo_warnings || {};
      Object.keys(w).forEach((k) => { out.textContent += ` · 告警 ${safe(k, 30)}: ${safe(w[k], 80)}`; });
      if (p.ok) fetchView('mirrors');
    });
  },

  purge(scope, target, out) {
    write('POST', '/api/cache/purge', { scope, ...(target ? { target } : {}) }, { confirm: true, key: 'w:purge' }).then((p) => {
      out.textContent = p.ok
        ? `已清理 ${inum(p.data && p.data.removed)} 项, 现用 ${fmtNum(p.data && p.data.watermark)}B`
        : `失败: ${safe(p.error && p.error.message, 120)}`;
      if (p.ok) fetchView('cache');
    });
  },

  saveConfig(patch, out) {
    write('PUT', '/api/config', { patch }, { confirm: true, key: 'w:config' }).then((p) => {
      out.textContent = p.ok ? `已写入覆盖层: ${((p.data || {}).applied || []).join(', ')}`
        : `失败: ${safe(p.error && p.error.message, 160)}`;
      if (p.ok) {
        const host = adminHost('config');
        if (host) loadAdmin('config', host);
      }
    });
  },

  issueToken(label, scopes) {
    write('POST', '/api/tokens', { label, scope: scopes }, { key: 'w:token' }).then((p) => {
      const root = viewRoot('summary');
      if (!root) return;
      if (!p.ok) {
        setNotice(`签发失败: ${safe(p.error && p.error.message, 120)}`);
        return;
      }
      const box = document.createElement('div');
      root.insertBefore(box, root.firstChild);
      renderTokenIssued(box, (p.data || {}).raw_token);
      const host = adminHost('tokens');
      if (host) loadAdmin('tokens', host);
    });
  },

  revokeToken(prefix) {
    write('DELETE', `/api/tokens/${encodeURIComponent(prefix)}`, {}, { confirm: true, key: `w:revoke:${prefix}` }).then((p) => {
      setNotice(p.ok ? `已吊销 ${safe(prefix, 16)}, 剩余 ${inum(p.data && p.data.remaining)} 个`
        : `吊销失败: ${safe(p.error && p.error.message, 120)}`);
      const host = adminHost('tokens');
      if (p.ok && host) {
        host.dataset.loaded = '';
        loadAdmin('tokens', host);
      }
    });
  },

  loadDecision(ref) {
    fetchView('decisions', { ref: String(ref || '').slice(0, 2000) });
  },

  /** 记住最近一次成功载荷, 供"新增还是编辑"这类判定用, 不必回读磁盘。 */
  remember(view, payload) {
    st.seen[view] = payload;
  },
};

// 把成功载荷交给 act, 让写操作能读到最新榜单而不必再发一次 GET。
const originalPaint = paint;
paint = function (view, payload) {
  act.remember(view, payload);
  return originalPaint(view, payload);
};

// ------------------------------------------------------------------
// 主题
// ------------------------------------------------------------------

function applyTheme(t) {
  st.theme = t;
  document.documentElement.dataset.theme = t;
  try {
    localStorage.setItem('gha-theme', t);
  } catch (e) {
    // 隐私模式禁用存储时主题只对本次生效: 偏好丢了无所谓, 报错才影响使用。
  }
}

function cycleTheme() {
  const order = ['auto', 'light', 'dark'];
  applyTheme(order[(order.indexOf(st.theme) + 1) % order.length]);
}

// ------------------------------------------------------------------
// 启动
// ------------------------------------------------------------------

function boot() {
  try {
    const saved = localStorage.getItem('gha-theme');
    if (saved === 'light' || saved === 'dark' || saved === 'auto') {
      document.documentElement.dataset.theme = saved;
      st.theme = saved;
    }
  } catch (e) {
    // 同上
  }

  const hash = (location.hash || '').replace('#', '');
  switchView(VIEWS.indexOf(hash) >= 0 ? hash : BOOT.view || 'summary', false);

  $$('.tab').forEach((t) => t.addEventListener('click', (ev) => {
    ev.preventDefault();
    switchView(t.dataset.view);
  }));

  const bt = $('#btn-theme');
  if (bt) bt.addEventListener('click', cycleTheme);
  const br = $('#btn-refresh');
  if (br) br.addEventListener('click', () => fetchView(st.view));

  const pf = $('#poll-factor');
  if (pf) {
    pf.addEventListener('change', () => {
      st.factor = Number(pf.value) || 0;
      clearTimeout(st.timer);
      if (st.factor === 0) {
        abortAll();
        setNotice('轮询已暂停');
        return;
      }
      st.fails = 0;
      st.backoffUntil = 0;
      setBanner(false);
      tick();
    });
  }

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
      st.timer = setTimeout(tick, 200);
    } else {
      // 后台页签: 停表 + 打断在飞的请求, 把 panel 桶的令牌让给前台那一页。
      clearTimeout(st.timer);
      abortAll();
    }
  });

  document.addEventListener('gha:auth-lost', () => {
    // 会话过期后接口一律被伪装成 404。面板必须主动停下并提示重新登录,
    // 否则会一直空转退避, 而运维看到的是"数字不动"这种最难归因的现象。
    clearTimeout(st.timer);
    setBanner(true, '会话已失效(接口按 404 伪装): 请重新登录。');
  });

  document.addEventListener('gha:ratelimited', (ev) => {
    const retry = Number((ev.detail || {}).retry || 30);
    st.backoffUntil = Date.now() + Math.max(5000, retry * 1000);
    setNotice(`panel 桶限流, ${retry}s 后继续`);
  });

  const clock = $('#meta-clock');
  if (clock) {
    const tickClock = () => {
      clock.textContent = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    };
    tickClock();
    setInterval(tickClock, 1000);
  }

  tick();
}

boot();
