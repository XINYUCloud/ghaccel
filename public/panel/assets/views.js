/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 四个视图的渲染器与行内操作。全部走 createElement + textContent,
 *             绝不拼 innerHTML: 视图里显示的是源域名、ref、curl 文案这类攻击者可控字符串。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 * @see       https://github.com/  完整版权与许可信息见仓库根目录 LICENSE
 */

import { fmtNum, fixed, inum, lineChart, hBars, watermarkBar, contributionBar } from './chart.js';

/** 中文常量表: v1 明确不做 i18n 框架, 加一层字典只会让人看不懂代码。 */
export const L = {
  title: { summary: '概览', mirrors: '源池', decisions: '决策追踪', cache: '缓存' },
  banner: { down: '数据链路中断', retrying: '正在退避重试' },
  breaker: { closed: '健康', open: '熔断中', half_open: '半开试探' },
  caps: { range: 'Range', follows_redirect_internally: '内部跟跳', json_api_ok: 'API JSON' },
  capState: { measured_true: '实测支持', measured_false: '实测不支持', claimed_unverified: '仅声称未实测', unknown: '未实测' },
  trust: { self: '自建', community: '社区已知', unknown: '未知来源', suspect: '不可信' },
  scenes: { raw: 'raw', release_asset: 'Release', archive: '归档', api_json: 'API', gist_raw: 'gist', unknown: '未知' },
  actions: {
    enable: '启用', disable: '停用', priority: '调 priority', probe: '立即探活', reset: '复位熔断',
    edit: '编辑', del: '删除', save: '保存', cancel: '取消', add: '新增源', purge: '清理',
    issue: '签发令牌', revoke: '吊销', apply: '应用覆盖',
  },
  confirm: {
    reset: '确认手动复位该源的熔断状态? 会清空连续失败计数并按冷却起点重新计。',
    del: '确认从源池删除该源? 历史观测保留, 但配置不再加载。',
    purgeAll: '确认清空全部缓存? 正在下载的分片不受影响, 但命中率会掉到 0。',
    purge: '确认执行该清理操作?',
    revoke: '确认吊销该令牌? 吊销后使用该令牌的会话同时作废, 无法找回。',
    config: '确认把这次改动写入在线覆盖层(overlay)? 它会一直生效到被配置文件覆盖或手动清除。',
  },
  hints: {
    probeQueued: '探活已入队(不阻塞面板进程): 由 bin/compact.php 或下一次真实请求完成实测。',
    coldStart: '冷启动中: 样本不足, 排序实质由人工先验主导。',
    staleData: '数据生成时间明显落后于当前时间, 可能是采集或压实停滞。',
  },
};

const MAXLEN = 120;

/** 显示前统一截断 + 剥控制字符。前端这一道是服务端 scrub 的复读, 不是替代。 */
export function safe(s, max) {
  const lim = max || MAXLEN;
  let t = s === null || s === undefined ? '' : String(s);
  t = t.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  if (t.length > lim) t = t.slice(0, lim) + '…';
  return t;
}

function mk(tag, attrs, kids) {
  const n = document.createElement(tag);
  if (attrs) {
    for (const k of Object.keys(attrs)) {
      const v = attrs[k];
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = String(v);
      else if (k.slice(0, 2) === 'data-') n.setAttribute(k, String(v));
      else n.setAttribute(k, String(v));
    }
  }
  const list = kids === undefined || kids === null ? [] : Array.isArray(kids) ? kids : [kids];
  for (const c of list) {
    if (c === null || c === undefined || c === false) continue;
    n.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
  }
  return n;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function card(title, kids, cls) {
  return mk('div', { class: `card ${cls || ''}` }, [title ? mk('h2', { class: 'h', text: title }) : null, ...((kids || []).filter(Boolean))]);
}

function metric(label, value, unit, cls, detail) {
  const n = mk('div', { class: 'n' + (cls ? ` ${cls}` : '') }, [String(value)]);
  if (unit) n.appendChild(mk('small', null, ' ' + unit));
  return mk('div', { class: `metric ${cls || ''}` }, [
    mk('div', { class: 'd', text: label }),
    n,
    detail ? mk('div', { class: 'd', text: detail }) : null,
  ]);
}

function chartBox(label, sizeCls) {
  return mk('div', { class: `chartbox ${sizeCls || ''}`, 'data-label': safe(label, 80) });
}

function badge(text, cls) {
  return mk('span', { class: `badge ${cls || ''}`, text: safe(text) });
}

function kvList(map, emptyText) {
  const keys = Object.keys(map || {});
  if (!keys.length) return mk('p', { class: 'muted', text: emptyText || '无' });
  const ul = mk('ul', { class: 'check' });
  for (const k of keys) {
    const v = map[k];
    ul.appendChild(mk('li', null, [
      mk('span', { class: 'k', text: safe(k, 60) }),
      mk('span', { class: 'v', text: safe(typeof v === 'object' ? JSON.stringify(v) : v, 240) }),
    ]));
  }
  return ul;
}

function metaLine(payload) {
  const m = payload && payload.meta ? payload.meta : {};
  const gen = m.generated_at ? new Date(Number(m.generated_at) * 1000).toLocaleTimeString('zh-CN', { hour12: false }) : '—';
  const ver = m.snapshot_version || '—';
  const now = Date.now() / 1000;
  const drift = m.generated_at ? Math.max(0, Math.round(now - Number(m.generated_at))) : null;
  const stale = drift !== null && drift > 90;
  return mk('p', { class: 'meta-line' }, [
    '数据生成 ',
    mk('code', { text: gen }),
    stale ? badge(` 落后 ${drift}s`, 'warn') : null,
    ' · snapshot_version ',
    mk('code', { text: safe(ver, 40) }),
    m.request_id ? ' · req ' : null,
    m.request_id ? mk('code', { text: safe(m.request_id, 12) }) : null,
  ]);
}

function timeAgo(ts) {
  const n = Number(ts) || 0;
  if (n <= 0) return '—';
  const d = Math.max(0, Math.round(Date.now() / 1000 - n));
  if (d < 60) return `${d}s 前`;
  if (d < 3600) return `${Math.round(d / 60)}m 前`;
  if (d < 86400) return `${Math.round(d / 3600)}h 前`;
  return `${Math.round(d / 86400)}d 前`;
}

function btn(label, cls, onClick, title) {
  const b = mk('button', { type: 'button', class: cls || '', title: title || '' });
  b.textContent = safe(label);
  b.addEventListener('click', onClick);
  return b;
}

/** 只读: 面板进程绝不做阻塞式上游请求, 所以探活/复位的结果以服务端返回为准。 */

// ------------------------------------------------------------------
// 概览
// ------------------------------------------------------------------

function renderSummary(root, payload, act) {
  const d = payload.data || {};
  const s = d.selfcheck || {};
  const cs = d.cold_start || {};

  const cards = mk('div', { class: 'grid' });
  cards.appendChild(card('请求速率', metric('QPS(窗口均值)', fixed(d.qps, 3), '', d.qps > 0 ? 'ok' : '', `窗口 ${d.window_s || 0}s 内 ${inum(d.requests_in_window)} 个请求`)));
  cards.appendChild(card('缓存命中率', metric('命中率', d.hit_rate === null ? '—' : (Number(d.hit_rate) * 100).toFixed(1), '%',
    d.hit_rate === null ? '' : d.hit_rate > 0.4 ? 'ok' : d.hit_rate > 0.1 ? 'warn' : 'bad',
    `${inum(d.requests_in_window)} 个请求 / 窗口 ${d.window_s || 0}s`)));
  cards.appendChild(card('P95 首字节', metric('P95 TTFB', d.p95_ttfb_ms === null ? '—' : fixed(d.p95_ttfb_ms, 1), 'ms',
    d.p95_ttfb_ms === null ? '' : d.p95_ttfb_ms > 3000 ? 'bad' : d.p95_ttfb_ms > 1500 ? 'warn' : 'ok',
    `样本 ${inum(d.samples_for_latency)} · P50 ${fixed(d.p50_ttfb_ms, 1)}ms`)));
  cards.appendChild(card('熔断源数', metric('熔断 / 半开', `${inum(d.breakers_open)} / ${inum(d.breakers_half_open)}`, '',
    (d.breakers_open || 0) > 0 ? 'bad' : 'ok', `源池 ${inum(d.sources_enabled)}/${inum(d.sources_total)} 启用`)));
  cards.appendChild(card('节省带宽', metric('窗口内直出字节', fmtNum(d.bytes_saved_window), 'B', 'ok',
    `窗口内总字节 ${fmtNum(d.bytes_total)}B（窗口外的累计值不可信, 日志按天轮转）`)));
  cards.appendChild(card('磁盘余量', metric('var/cache 剩余', (d.disk_free_bytes || -1) >= 0 ? fmtNum(d.disk_free_bytes) : '未知', 'B',
    (d.disk_free_bytes || -1) >= 0 && d.disk_free_bytes < 1073741824 ? 'bad' : 'ok',
    `已用 ${fmtNum(d.cache_used_bytes)}B / 上限 ${fmtNum(d.cache_max_bytes)}B`)));
  cards.appendChild(card('快照与日志', metric('状态快照', d.snapshot_version ? safe(d.snapshot_version, 24) : '—', '', d.snapshot_version ? '' : 'bad',
    `压实于 ${d.compacted_at ? timeAgo(d.compacted_at) : '—'} · 尾部读到 ${inum(d.journal_rows)} 行观测`)));

  const series = d.series || {};
  const boxQ = chartBox('请求与命中', 'lg');
  const boxL = chartBox('P95 首字节', 'sm');
  const charts = card('窗口内趋势', [boxQ, boxL, mk('div', { class: 'legend' }, [
    mk('span', null, [mk('i', { class: 'a' }), '请求']),
    mk('span', null, [mk('i', { class: 'b' }), '命中']),
    mk('span', null, [mk('i', { class: 'c' }), '失败']),
  ])]), 'full');

  const sc = card('环境自检', [
    mk('p', { class: 'meta-line', text: 'critical 非空时入口直接回 500; 这里原样显示 Bootstrap::selfCheck() 的结果。' }),
    mk('h3', { class: 'h3', text: `严重项 (${Object.keys(s.critical || {}).length})` }),
    kvList(s.critical, '无'),
    mk('h3', { class: 'h3', text: `告警 (${Object.keys(s.warnings || {}).length})` }),
    kvList(s.warnings, '无'),
    mk('details', null, [
      mk('summary', { text: '运行信息 info' }),
      kvList(s.info || {}),
    ]),
  ], 'full');

  const cold = card('冷启动标注', [
    mk('p', { class: cs.cold ? 'warnline' : 'meta-line', text: safe(cs.note || L.hints.coldStart, 240) }),
    mk('p', { class: 'meta-line' }, [
      '全局样本 ', mk('code', { text: String(cs.global_samples || 0) }),
      ' / 判定阈值 ', mk('code', { text: String(cs.min_sample_for_rank || 30) }),
    ]),
  ]);

  const warn = (d.warnings || []).length
    ? card('运维提醒', (d.warnings || []).map((w) => mk('p', { class: 'warnline', text: safe(w, 240) })), 'full')
    : null;

  const boxMe = mk('div', { class: 'full' });
  const admin = card('会话 · 令牌 · 在线覆盖层', [boxMe], 'full');

  root.append(cards, charts, mk('div', { class: 'grid wide' }, [sc, cold, warn].filter(Boolean)), admin, metaLine(payload));

  // 图在容器可见之后才画: 隐藏时 getBoundingClientRect 是 0, 画出来就是空图。
  requestAnimationFrame(() => {
    lineChart(boxQ, [
      { name: 'requests', points: series.requests || [], area: true },
      { name: 'hits', points: series.hits || [], cls: 'b' },
      { name: 'failures', points: series.failures || [], cls: 'c' },
    ], { unit: '', ticks: 4, max: Math.max(1, ...(series.requests || [])) });
    lineChart(boxL, [{ name: 'p95', points: series.p95_ttfb || [], cls: 'c' }], { unit: 'ms', ticks: 3 });
  });

  loadAdmin(boxMe, act);
}

/** 概览底部的管理块: 三个接口按需展开, 免得默认每次轮询多打三枪。 */
function loadAdmin(host, act) {
  clear(host);
  const mkDet = (label, id, name) => {
    const det = mk('details');
    det.appendChild(mk('summary', { text: label }));
    const inner = mk('div', { id });
    det.appendChild(inner);
    det.addEventListener('toggle', () => {
      if (det.open && !inner.dataset.loaded) act.load(name, inner);
    });
    return { det, inner };
  };
  const me = mkDet('当前会话与活动会话', 'admin-me', 'me');
  const tok = mkDet('管理令牌', 'admin-tokens', 'tokens');
  const cfg = mkDet('在线配置覆盖层', 'admin-config', 'config');
  host.append(me.det, tok.det, cfg.det);
}

export function renderMe(root, payload, act) {
  const d = payload.data || {};
  clear(root);
  const row = mk('ul', { class: 'plist' });
  row.appendChild(mk('li', null, [
    badge(d.can_write ? 'read+write' : 'read', d.can_write ? 'ok' : 'off'),
    mk('code', { text: safe(d.selector_prefix, 16) }),
    safe(d.label, 64),
    'UA ' + safe(d.ua_summary, 80),
    'IP 摘要 ' + safe(d.ip_hash, 20),
    '最近活动 ' + timeAgo(d.last_seen_at),
  ]));
  root.appendChild(mk('p', { class: 'meta-line', text: `会话 idle ${d.session_idle_s || 0}s / 绝对 ${d.session_abs_s || 0}s` }));
  root.appendChild(mk('h3', { class: 'h3', text: '同机活跃会话(发现不属于你的 IP 前缀就说明会话被异地使用)' }));
  const peers = mk('ul', { class: 'plist' });
  (d.peers || []).forEach((p) => {
    peers.appendChild(mk('li', { class: p.self ? 'mine' : '' }, [
      p.self ? badge('本机当前', 'ok') : badge('其他', 'warn'),
      mk('code', { text: safe(p.ip_prefix, 40) }),
      'ua#', mk('code', { text: safe(p.ua_digest, 12) }),
      safe(p.label, 40),
      'seen ' + timeAgo(p.last_seen_at),
      (p.scopes || []).join(','),
    ]));
  });
  root.appendChild(peers.length ? peers : mk('p', { class: 'muted', text: '无' }));
  root.appendChild(metaLine(payload));
  root.appendChild(btn('刷新会话', 'ghost', () => act.load('me')));
}

export function renderTokens(root, payload, act) {
  const d = payload.data || {};
  clear(root);
  const list = mk('ul', { class: 'plist' });
  (d.rows || []).forEach((t) => {
    list.appendChild(mk('li', null, [
      mk('code', { text: safe(t.selector_prefix, 16) }),
      safe(t.label, 64),
      badge((t.scopes || []).join(',') || '无作用域', (t.scopes || []).indexOf('write') >= 0 ? 'warn' : 'off'),
      '签发 ' + timeAgo(t.created_at),
      '最后用 ' + timeAgo(t.last_used_at),
      btn(L.actions.revoke, 'danger', () => {
        if (!window.confirm(L.confirm.revoke)) return;
        act.revokeToken(t.selector_prefix);
      }),
    ]));
  });
  root.appendChild(list.length ? list : mk('p', { class: 'muted', text: '尚未签发任何令牌。可用 bin/token.php issue, 或在这里签发。' }));
  root.appendChild(mk('p', { class: 'note', text: safe(d.note, 240) }));

  const label = mk('input', { type: 'text', placeholder: '用途标签, 例如 办公机', maxlength: '64' });
  const scope = mk('select', null, [mk('option', { value: 'read', text: 'read' }), mk('option', { value: 'write', text: 'read+write' })]);
  root.appendChild(mk('div', { class: 'row' }, [label, scope, btn(L.actions.issue, 'primary', () => act.issueToken(label.value, scope.value === 'write' ? ['read', 'write'] : ['read']))]));
  root.appendChild(metaLine(payload));
}

export function renderTokenIssued(root, raw) {
  clear(root);
  const box = mk('div', { class: 'card full' });
  box.appendChild(mk('h3', { class: 'h3', text: '令牌明文 —— 只显示这一次' }));
  box.appendChild(mk('pre', { class: 'mono', text: safe(raw, 120) }));
  box.appendChild(mk('p', { class: 'warnline', text: '服务端只存 sha256 摘要, 丢失无法找回, 只能重签。现在把它复制走。' }));
  root.appendChild(box);
}

export function renderConfig(root, payload, act) {
  const d = payload.data || {};
  clear(root);
  root.appendChild(mk('p', { class: 'meta-line', text: `可改顶层段: ${(d.editable_top || []).join(', ')} · 面板拒绝改 panel.${(d.panel_denied || []).join('/')}` }));
  if (d.base_origin_configured === false) {
    root.appendChild(mk('p', { class: 'warnline', text: 'app.base_origin 未配置: 浏览器的写请求会因缺少同源基准被 CSRF 校验拒绝。' }));
  }

  const det = mk('details');
  det.appendChild(mk('summary', { text: '在线覆盖层 overlay.json(当前生效的面板改动)' }));
  det.appendChild(kvList(d.overlay || {}, '覆盖层为空: 一切走配置文件'));
  root.appendChild(det);

  const segSel = mk('select', null, (d.editable_top || []).map((k) => mk('option', { value: k, text: k })));
  const keyIn = mk('input', { type: 'text', placeholder: '点号路径, 如 algo.wilson_z' });
  const valIn = mk('input', { type: 'text', placeholder: '值(JSON, 如 1.0 或 {"raw":0.8})' });
  const out = mk('p', { class: 'muted' });
  const applyBtn = btn(L.actions.apply + ' (需确认)', 'primary', () => {
    let parsed;
    try {
      parsed = JSON.parse(valIn.value);
    } catch (e) {
      parsed = valIn.value;
    }
    const seg = segSel.value;
    const path = keyIn.value.split('.').slice(1);
    if (!path.length) {
      out.textContent = '路径必须是 段.键 形式, 例如 algo.wilson_z';
      return;
    }
    const patch = { [seg]: {} };
    let cur = patch[seg];
    for (let i = 0; i < path.length - 1; i++) {
      cur[path[i]] = {};
      cur = cur[path[i]];
    }
    cur[path[path.length - 1]] = parsed;
    if (!window.confirm(L.confirm.config)) return;
    act.saveConfig(patch, out);
  });
  root.appendChild(mk('div', { class: 'row' }, [segSel, keyIn, valIn, applyBtn]));
  root.appendChild(out);

  const sec = mk('details');
  sec.appendChild(mk('summary', { text: '当前生效配置(密钥类值已脱敏)' }));
  const pre = mk('pre', { class: 'mono', text: '' });
  pre.textContent = JSON.stringify(d.sections || {}, null, 2);
  sec.appendChild(pre);
  root.appendChild(sec);
  root.appendChild(metaLine(payload));
}

// ------------------------------------------------------------------
// 源池
// ------------------------------------------------------------------

export function renderMirrors(root, payload, act) {
  const d = payload.data || {};
  clear(root);

  const warnKeys = Object.keys(d.warnings || {});
  if (warnKeys.length) {
    root.appendChild(card('源表告警', [kvList(d.warnings)], 'full'));
  }

  const wrap = mk('div', { class: 'tblwrap' });
  const tbl = mk('table', { class: 'tbl' });
  const head = mk('tr', null, [
    '源 id', '拼接形态', '支持场景', 'trust', '熔断/冷却', '样本', 'Wilson 下界',
    'TTFB EWMA / P85', '吞吐', '实测能力位', '连续硬失败', '最近失败分型', '操作',
  ].map((h) => mk('th', { text: h })));
  const thead = mk('thead', null, head);
  const tbody = mk('tbody');
  tbl.append(thead, tbody);
  wrap.appendChild(tbl);

  (d.rows || []).forEach((r) => tbody.appendChild(mirrorRow(r, act, (d.pending_probes || []).indexOf(r.id) >= 0)));

  root.appendChild(card(`源池榜单 (${(d.rows || []).length})`, [wrap], 'full'));
  root.appendChild(mirrorForm(act));
  root.appendChild(metaLine(payload));
}

function capCell(r) {
  const box = mk('span');
  const state = r.caps_state || {};
  Object.keys(L.caps).forEach((k) => {
    const st = state[k] || 'unknown';
    const cls = st === 'measured_true' ? 'ok' : st === 'measured_false' ? 'bad' : st === 'claimed_unverified' ? 'warn' : 'off';
    box.appendChild(badge(`${L.caps[k]}:${L.capState[st]}`, cls));
    box.appendChild(document.createTextNode(' '));
  });
  return box;
}

function mirrorRow(r, act, pendingProbe) {
  const tr = mk('tr', { class: `${r.enabled ? '' : 'off'} ${r.breaker === 'open' ? 'tripled' : ''}` });
  const idCell = mk('td', null, [
    mk('code', { text: safe(r.id, 60) }),
    mk('br'),
    mk('span', { class: 'muted mono', text: safe((r.base_host || {}).display, 60) }),
  ]);
  if ((r.base_host || {}).idn) {
    idCell.appendChild(mk('br'));
    idCell.appendChild(badge('punycode ' + safe(r.base_host.punycode, 60), 'idn'));
  }
  if (pendingProbe) idCell.appendChild(badge('待探活', 'warn'));

  const mode = mk('td', null, [
    badge(r.mode_label || r.mode, 'off'),
    mk('br'),
    mk('span', { class: 'muted mono', text: safe(r.example, 120) }),
  ]);

  const scenes = mk('td', null, (r.scenes || []).map((s) => badge(L.scenes[s] || s, 'off')));

  const trust = mk('td', null, [badge(L.trust[r.trust] || r.trust, r.trust === 'suspect' ? 'bad' : r.trust === 'self' ? 'ok' : 'off'),
    mk('br'), mk('span', { class: 'muted', text: `priority ${r.priority}` })]);

  const brk = mk('td', null, [
    badge(L.breaker[r.breaker] || r.breaker, r.breaker === 'closed' ? 'ok' : r.breaker === 'half_open' ? 'warn' : 'bad'),
    mk('br'),
    r.cooldown_left_s > 0 ? mk('span', { class: 'mono', text: `冷却 ${Math.ceil(r.cooldown_left_s)}s` }) : mk('span', { class: 'muted', text: '无冷却' }),
    mk('br'),
    mk('span', { class: 'muted', text: `trip ${r.trip_count || 0} · 半开成功 ${r.consec_probe_ok || 0}` }),
  ]);

  const samp = mk('td', { class: 'num' }, [
    String(r.sample_count || 0),
    r.cold_start ? mk('br') : null,
    r.cold_start ? badge('冷启动', 'warn') : null,
  ]);

  const wil = mk('td', { class: 'num' }, [
    fixed(r.wilson_lower, 4),
    mk('br'),
    mk('span', { class: 'muted', text: `${r.successes || 0}/${r.sample_count || 0}` }),
  ]);

  const ttfb = mk('td', { class: 'num' }, [
    `${fixed(r.ttfb_ewma_ms, 1)} / ${fixed(r.ttfb_p85_ms, 1)}`,
    mk('br'),
    mk('span', { class: 'muted', text: `保守 ${fixed(r.conservative_ttfb_ms, 1)}ms` }),
  ]);

  const thr = mk('td', { class: 'num' }, [
    `${fmtNum(r.thr_bps)}B/s`,
    mk('br'),
    mk('span', { class: 'muted', text: `P10 ${fmtNum(r.thr_p10_bps)}B/s` }),
  ]);

  const err = mk('td', null, [
    r.last_failure_kind ? badge(safe(r.last_failure_kind, 24), 'bad') : badge('无', 'off'),
    r.last_http_status ? mk('br') : null,
    r.last_http_status ? mk('span', { class: 'muted mono', text: `HTTP ${r.last_http_status}` }) : null,
    r.last_error ? mk('br') : null,
    r.last_error ? mk('span', { class: 'muted', text: safe(r.last_error, 120) }) : null,
  ]);

  const acts = mk('td', { class: 'acts' }, [
    btn(r.enabled ? L.actions.disable : L.actions.enable, 'ghost', () => act.mirrorAction(r.id, r.enabled ? 'disable' : 'enable')),
    ' ',
    btn(L.actions.probe, 'ghost', () => act.mirrorAction(r.id, 'probe'), '写控制事件, 不阻塞面板进程'),
    ' ',
    btn(L.actions.reset, 'ghost', () => {
      if (!window.confirm(L.confirm.reset)) return;
      act.mirrorAction(r.id, 'reset_breaker', {}, true);
    }),
    mk('br'),
    btn(L.actions.del, 'danger', () => {
      if (!window.confirm(L.confirm.del)) return;
      act.deleteMirror(r.id);
    }),
  ]);

  const prio = mk('input', { type: 'number', min: '1', max: '100', value: String(r.priority || 50), size: '3' });
  acts.appendChild(mk('br'));
  acts.appendChild(mk('span', { class: 'row' }, [prio, btn(L.actions.priority, 'ghost', () => act.setPriority(r.id, Number(prio.value)))]));

  tr.append(idCell, mode, scenes, trust, brk, samp, wil, ttfb, thr, mk('td', null, capCell(r)), mk('td', { class: 'num', text: String(r.consec_hard_fail || 0) }), err, acts);
  return tr;
}

function mirrorForm(act) {
  const det = mk('details', { class: 'card full' });
  det.appendChild(mk('summary', { text: L.actions.add + ' / 编辑源' }));
  const f = mk('div', { class: 'form' });
  const mk_ = (label, node) => { f.appendChild(mk('label', { class: 'fld' }, [label, node])); return node; };
  const id = mk_('id(slug)', mk('input', { type: 'text', name: 'id', placeholder: 'my-mirror' }));
  const baseUrl = mk_('base_url', mk('input', { type: 'text', name: 'base_url', placeholder: 'https://mirror.example.com' }));
  const mode = mk_('mode', mk('select', { name: 'mode' }, ['prefix_full', 'prefix_path', 'host_replace', 'template'].map((v) => mk('option', { value: v, text: v }))));
  const tmpl = mk_('url_template(仅 template)', mk('input', { type: 'text', name: 'url_template', placeholder: '{base}/{url}' }));
  const hosts = mk_('hosts(逗号分隔精确域名)', mk('input', { type: 'text', name: 'hosts', placeholder: 'github.com,raw.githubusercontent.com' }));
  const scenesBox = mk('div', { class: 'row' }, Object.keys(L.scenes).filter((k) => k !== 'unknown').map((k) => mk('label', { class: 'fld checkbox' }, [
    mk('input', { type: 'checkbox', value: k }), L.scenes[k],
  ])));
  f.appendChild(mk('div', { class: 'fld' }, ['scenes', scenesBox]));
  const trust = mk_('trust', mk('select', { name: 'trust' }, ['self', 'community', 'unknown'].map((v) => mk('option', { value: v, text: L.trust[v] }))));
  const prio = mk_('priority(1-100)', mk('input', { type: 'number', name: 'priority', min: '1', max: '100', value: '50' }));
  const region = mk_('region', mk('input', { type: 'text', name: 'region', value: 'cn_broadband' }));
  const minInt = mk_('min_interval_ms', mk('input', { type: 'number', name: 'min_interval_ms', min: '0', value: '150' }));
  const maxBytes = mk_('max_size_bytes', mk('input', { type: 'number', name: 'max_size_bytes', min: '0', value: '0' }));
  const blocked = mk_('blocked_ext', mk('input', { type: 'text', name: 'blocked_ext', placeholder: 'exe,apk' }));
  const noteIn = mk_('owner_note', mk('input', { type: 'text', name: 'owner_note', maxlength: '200' }));
  const enabled = mk('label', { class: 'fld checkbox' }, [mk('input', { type: 'checkbox', name: 'enabled', checked: 'checked' }), '启用']);
  f.appendChild(enabled);

  const out = mk('p', { class: 'muted' });
  

  const submit = btn('提交(落 overlay, 不写配置文件)', 'primary', () => {
    const body = {
      id: id.value.trim(),
      base_url: baseUrl.value.trim(),
      mode: mode.value,
      url_template: tmpl.value.trim(),
      hosts: hosts.value.split(',').map((x) => x.trim().toLowerCase()).filter(Boolean),
      scenes: Array.from(scenesBox.querySelectorAll('input:checked')).map((x) => x.value),
      trust: trust.value,
      priority: Number(prio.value),
      region: region.value.trim(),
      min_interval_ms: Number(minInt.value),
      max_size_bytes: Number(maxBytes.value),
      blocked_ext: blocked.value.split(',').map((x) => x.trim().toLowerCase()).filter(Boolean),
      owner_note: noteIn.value.trim(),
      enabled: enabled.querySelector('input').checked,
    };
    act.saveMirror(body, out);
  });
  det.append(f, mk('div', { class: 'row' }, [submit, out]));
  return det;
}

// ------------------------------------------------------------------
// 决策追踪
// ------------------------------------------------------------------

export function renderDecisions(root, payload, act) {
  const d = payload.data || {};
  clear(root);

  const input = mk('input', { type: 'text', value: safe(d.ref_input, 200), placeholder: '/gh/owner/repo@ref/path 或 /https://github.com/…', size: '60' });
  const run = btn('重放选路', 'primary', () => act.loadDecision(input.value));
  root.appendChild(mk('div', { class: 'row' }, [input, run]));
  root.appendChild(mk('p', { class: 'note', text: safe(d.note, 240) }));
  if (d.parse_error) {
    root.appendChild(mk('p', { class: 'warnline', text: `解析失败: ${safe(d.parse_error, 200)}` }));
  }

  const refLine = mk('p', { class: 'meta-line' }, [
    '场景 ', mk('code', { text: safe(d.scene, 30) }),
    ' · 身份 ', mk('code', { text: safe(d.identity_kind, 30) }),
    ' · 键摘要 ', mk('code', { text: safe(d.ref_digest, 20) }),
  ]);
  const up = d.upstream_host || {};
  if (up.display) {
    refLine.appendChild(document.createTextNode(' · 上游 host '));
    refLine.appendChild(mk('code', { text: safe(up.display, 120) }));
    if (up.idn) {
      refLine.appendChild(document.createTextNode(' punycode '));
      refLine.appendChild(mk('code', { text: safe(up.punycode, 120) }));
      refLine.appendChild(badge('IDN: 同形字风险, 请对照两列', 'idn'));
    }
  }
  root.appendChild(refLine);

  const plan = (d.decision || {}).plan || {};
  const ranked = plan.ranked || [];
  if (!ranked.length) {
    root.appendChild(mk('p', { class: 'warnline', text: '重放结果为空 ranked —— 全部源被硬约束筛掉, 看下面的剔除原因。' }));
  } else {
    const wrap = mk('div', { class: 'tblwrap' });
    const tbl = mk('table', { class: 'tbl' });
    tbl.appendChild(mk('thead', null, mk('tr', null, ['#', '源', '总分', 'breakdown(权重 × 归一值 = 贡献)', '贡献条', '预测 ms', '放宽'].map((h) => mk('th', { text: h })))));
    const tb = mk('tbody');
    ranked.forEach((row, i) => {
      const factors = row.factors || {};
      const items = Object.keys(factors).map((k) => {
        const f = factors[k];
        return mk('div', { class: 'sumline' }, [
          `${safe(f.label || k, 24)} `,
          mk('b', { text: `${fixed(f.weight, 4)}×${fixed(f.value, 4)}=${fixed(f.contrib, 6)}` }),
        ]);
      });
      const bar = chartBox(`贡献分解 ${safe(row.id, 40)}`, 'sm');
      const tr = mk('tr', null, [
        mk('td', { class: 'num', text: String(i) }),
        mk('td', null, mk('code', { text: safe(row.id, 60) })),
        mk('td', { class: 'num' }, [
          fixed(row.score, 6),
          mk('br'),
          mk('span', { class: row.sum_matches_score ? 'muted' : 'warnline', text: row.sum_matches_score ? 'Σ 一致' : 'Σ 不一致!' }),
        ]),
        mk('td', { class: 'brk' }, items),
        mk('td', null, bar),
        mk('td', { class: 'num', text: fixed(row.predicted_ms, 0) }),
        mk('td', null, (row.relaxed || []).map((x) => badge(safe(x, 40), 'warn'))),
      ]);
      tb.appendChild(tr);
      requestAnimationFrame(() => contributionBar(bar, Object.keys(factors).map((k) => factors[k]), row.score_exact ?? row.score));
    });
    tbl.appendChild(tb);
    wrap.appendChild(tbl);
    root.appendChild(card('ranked 候选', [wrap], 'full'));
  }

  const excl = d.excluded || [];
  const exBox = card(`excluded 剔除原因 (${excl.length})`, [
    excl.length ? kvList(excl.reduce((acc, e) => {
      const k = `${safe(e.id, 40)} · ${safe(e.code, 40)}`;
      acc[k] = `${safe(e.detail, 160)}${e.retry_after_s !== undefined && e.retry_after_s !== null ? ` · 剩 ${e.retry_after_s}s` : ''}`;
      return acc;
    }, {}), '无') : null,
  ], 'full');
  root.appendChild(exBox);

  root.appendChild(mk('p', { class: 'meta-line' }, [
    '放宽档 ', mk('code', { text: safe((d.relaxed_flags || []).join(',') || '无', 120) }),
    ' · 冷启动 ', (d.cold_start ? '是' : '否'),
    ' · top1-top2 分差 ', mk('code', { text: fixed(d.score_gap, 6) }),
    ' · 选路耗时 ', `${fixed(d.elapsed_ms, 2)}ms`,
  ]));

  const att = (d.decision || {}).attempts || [];
  const attWrap = mk('div');
  att.forEach((a) => {
    const det = mk('details', { class: 'card' });
    det.appendChild(mk('summary', { text: `${safe(a.req, 12)}… ${new Date((Number(a.at) || 0) * 1000).toLocaleTimeString('zh-CN', { hour12: false })} ref#${safe(a.ref_digest, 16)} → ${safe(a.outcome, 60)}` }));
    const t = mk('table', { class: 'tbl' });
    t.appendChild(mk('thead', null, mk('tr', null, ['源', '事件', '分型', '状态', 'TTFB', '字节', '缓存', '模式', '预算', '跳', '已提交'].map((h) => mk('th', { text: h })))));
    const tb = mk('tbody');
    (a.events || []).forEach((ev) => {
      tb.appendChild(mk('tr', null, [
        mk('td', null, mk('code', { text: safe(ev.source, 60) })),
        mk('td', { text: safe(ev.type, 30) }),
        mk('td', { text: safe(ev.kind, 30) }),
        mk('td', { class: 'num', text: String(ev.status || 0) }),
        mk('td', { class: 'num', text: `${fixed(ev.ttfb_ms, 1)}ms` }),
        mk('td', { class: 'num', text: inum(ev.bytes) }),
        mk('td', { text: safe(ev.cache, 24) }),
        mk('td', { text: safe(ev.mode, 20) }),
        mk('td', { class: 'num', text: `${ev.budget_ms || 0}ms` }),
        mk('td', { class: 'num', text: String(ev.hops || 0) }),
        mk('td', null, badge(ev.committed ? '已发出' : '未发出', ev.committed ? 'warn' : 'off')),
      ]));
    });
    t.appendChild(tb);
    det.appendChild(t);
    attWrap.appendChild(det);
  });
  root.appendChild(card(`最近真实请求 (${att.length})`, [att.length ? attWrap : mk('p', { class: 'muted', text: '观测流暂无记录: 还没有真实请求, 或日志刚被压实轮转。' })], 'full'));
  root.appendChild(metaLine(payload));
}

// ------------------------------------------------------------------
// 缓存
// ------------------------------------------------------------------

export function renderCache(root, payload, act) {
  const d = payload.data || {};
  const w = d.watermark || {};
  clear(root);

  const cards = mk('div', { class: 'grid' });
  cards.appendChild(card('命中率(窗口)', metric('缓存命中', d.hit_rate_window === null ? '—' : (Number(d.hit_rate_window) * 100).toFixed(1), '%',
    d.hit_rate_window === null ? '' : d.hit_rate_window > 0.4 ? 'ok' : 'warn', `窗口内直出 ${fmtNum(d.bytes_saved_window)}B`)));
  cards.appendChild(card('条目', metric('已完成条目', inum(w.entries), '', '', `.part 字节 ${fmtNum(w.partial_bytes)}B`)));
  cards.appendChild(card('半成品', metric('.part 文件', inum(d.partial_files), '', d.partial_files > 20 ? 'warn' : '',
    `隔离区 ${inum(d.quarantine_files)} 个`)));
  cards.appendChild(card('磁盘余量', metric('剩余', w.disk_free >= 0 ? fmtNum(w.disk_free) : '未知', 'B',
    w.disk_free >= 0 && w.disk_free < 1073741824 ? 'bad' : 'ok', `淘汰累计 ${fmtNum((d.usage || {}).total_evicted)}B`)));

  const wmBox = chartBox('容量水位', 'sm');
  const ratioCard = card('容量水位三档', [
    wmBox,
    mk('p', { class: 'meta-line' }, [
      `已用 ${fmtNum(w.used)}B / ${fmtNum(w.max)}B = ${((Number(w.ratio) || 0) * 100).toFixed(2)}%`,
      w.stop_writing ? badge('已到停写档', 'bad') : null,
    ]),
    mk('div', { class: 'barsheet' }, [
      mk('span', { class: 'lbl', text: 'soft 后台淘汰' }), mk('span', null, barText(w.soft)),
      mk('span', { class: 'val', text: fmtNum(w.soft_bytes) + 'B' }),
      mk('span', { class: 'lbl', text: 'hard 写前同步' }), mk('span', null, barText(w.hard)),
      mk('span', { class: 'val', text: fmtNum(w.hard_bytes) + 'B' }),
      mk('span', { class: 'lbl', text: 'stop 停写' }), mk('span', null, barText(w.stop)),
      mk('span', { class: 'val', text: fmtNum(w.stop_bytes) + 'B' }),
    ]),
    mk('p', { class: 'muted', text: `水位扫描时间 ${w.scanned_at ? new Date(w.scanned_at * 1000).toLocaleTimeString('zh-CN', { hour12: false }) : '—'} · 缓存${d.enabled ? '已启用' : '已被配置关闭'}` }),
  ], 'full');

  const sceneBox = chartBox('按场景分布', 'lg');
  const scenesCard = card('条目按场景分布', [
    sceneBox,
    mk('p', { class: 'muted', text: `扫描 meta ${d.scanned_meta || 0} 个${d.scan_truncated ? '(已截断, 大缓存目录只看前若干条)' : ''}` }),
  ], 'full');

  const ttlRows = Object.keys(d.ttl_by_scene || {}).map((k) => mk('li', null, [
    mk('code', { text: safe(k, 30) }), ' fresh ', mk('code', { text: String(d.ttl_by_scene[k]) }), 's',
  ]));
  const ttlCard = card('按场景 fresh TTL', [mk('ul', { class: 'tight' }, ttlRows)]);

  root.append(cards, mk('div', { class: 'grid wide' }, [ratioCard, scenesCard, ttlCard]));

  // 清理: 三档 scope + 需要 confirm。
  const form = mk('div', { class: 'card full' });
  form.appendChild(mk('h2', { class: 'h', text: '清理操作(危险, 需二次确认)' }));
  const scope = mk('select', null, [
    mk('option', { value: 'all', text: 'all — 整个缓存' }),
    mk('option', { value: 'ref', text: 'ref — 单个引用/缓存键' }),
    mk('option', { value: 'prefix', text: 'prefix — 缓存键十六进制前缀' }),
    mk('option', { value: 'expired', text: 'expired — 过期条目' }),
    mk('option', { value: 'partial', text: 'partial — 只清半成品' }),
    mk('option', { value: 'scene', text: 'scene — 按场景' }),
    mk('option', { value: 'source', text: 'source — 按源' }),
  ]);
  const target = mk('input', { type: 'text', placeholder: 'ref 原文 / 64 位键 / hex 前缀 / 场景名 / 源 id' });
  const out = mk('span', { class: 'muted' });
  form.appendChild(mk('div', { class: 'row' }, [
    scope, target,
    btn(L.actions.purge, 'danger', () => {
      const sc = scope.value;
      if (sc !== 'all' && sc !== 'expired' && sc !== 'partial' && !target.value.trim()) {
        out.textContent = '该 scope 需要 target';
        return;
      }
      const msg = sc === 'all' ? L.confirm.purgeAll : L.confirm.purge;
      if (!window.confirm(msg)) return;
      act.purge(sc, target.value.trim(), out);
    }),
    out,
  ]));
  form.appendChild(mk('p', { class: 'note', text: '清理只删本机缓存字节, 不动观测日志与源统计。prefix 档单次最多删 500 条, 防止一次点击把库扫穿。' }));

  root.append(form, metaLine(payload));

  requestAnimationFrame(() => {
    watermarkBar(wmBox, { ratio: Number(w.ratio) || 0, soft: Number(w.soft) || 0.7, hard: Number(w.hard) || 0.85, stop: Number(w.stop) || 0.95 });
    const rows = (d.by_scene || []).map((s) => ({
      label: `${(L.scenes[s.scene] || s.scene)} ${s.entries}`,
      value: Number(s.bytes) || 0,
      sub: `${fmtNum(s.bytes)}B · fresh ${s.fresh}`,
    }));
    hBars(sceneBox, rows, { unit: 'B', emptyText: '缓存为空' });
  });
}

function barText(v) {
  const b = mk('div', { class: 'bar' });
  const i = mk('i');
  i.style.setProperty('width', `${Math.max(0, Math.min(100, (Number(v) || 0) * 100)).toFixed(1)}%`);
  b.appendChild(i);
  b.appendChild(mk('span', { class: 'mark', 'data-at': String(v) }));
  return b;
}

export { renderSummary, card, metaLine, chartBox, safe as esc };
