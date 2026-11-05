/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 面板唯一的网络出入口。拼 URL、带 CSRF、超时与 AbortController、把
 *             {ok,data,meta} / {ok,error} 两种信封归一成 Promise 结果。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 * @see       https://github.com/  完整版权与许可信息见仓库根目录 LICENSE
 */

/**
 * 为什么所有请求都要过这里:
 *  1. CSRF Token 绑的是"方法 + 路由模板", 前端必须做与服务端同一套归一化, 否则 PUT
 *     /mirrors/abc 拿 /mirrors/{id} 的 Token 时算错一位就永远 403, 而这种 403 在浏览器
 *     里只表现为"按钮没反应"。归一化只允许存在于这一个函数里。
 *  2. AbortController 集中管理: 同类请求(同一个 key)后发的那次必须取消前一次, 不然轮询
 *     慢于间隔时请求会叠加, 一个页签就能把 panel 桶的令牌打光并把自己的界面卡死。
 *  3. 不用 eval / new Function, 也不把任何响应当代码: 数据只走 JSON.parse(天然安全)。
 */

const bootEl = document.getElementById('boot');
if (!bootEl) {
  throw new Error('面板缺少 boot 数据块');
}

export const BOOT = JSON.parse(bootEl.textContent || '{}');
export const PREFIX = BOOT.prefix || '/panel';
const CSRF_MAP = BOOT.csrf || {};
const META_CSRF = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';

/** 并发中的请求: key -> AbortController。 */
const inflight = new Map();

/** 具体路径 -> CSRF 绑定模板。与 Api::csrfPathFor 保持逐字符一致。 */
export function csrfPath(path) {
  // boot 里的键是"面板前缀 + 动作模板"(不带 /api), 而这里的入参是不带前缀的 API 相对路径。
  // 两头都要收敛到同一个串, 否则服务端按第三种形态算 HMAC, 面板每一个写请求都会 403。
  let p = path.replace(/^\/api(?=\/|$)/, '');
  if (/\/mirrors\/[^/]+\/action$/.test(p)) {
    p = p.replace(/\/mirrors\/[^/]+\/action$/, '/mirrors/{id}/action');
  } else if (/\/mirrors\/[^/]+$/.test(p)) {
    p = p.replace(/\/mirrors\/[^/]+$/, '/mirrors/{id}');
  } else if (/\/tokens\/[^/]+$/.test(p)) {
    p = p.replace(/\/tokens\/[^/]+$/, '/tokens/{prefix}');
  }
  return PREFIX + p;
}

export function csrfFor(method, path) {
  const key = `${method.toUpperCase()}:${csrfPath(path)}`;
  return CSRF_MAP[key] || META_CSRF;
}

function qs(params) {
  if (!params) return '';
  const p = [];
  for (const k of Object.keys(params)) {
    const v = params[k];
    if (v === null || v === undefined || v === '') continue;
    p.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
  }
  return p.length ? `?${p.join('&')}` : '';
}

/** 网络层错误也归一成 Api 的信封形状, 调用方只处理一种结构。 */
function failure(code, message, status) {
  return { ok: false, error: { code, message, request_id: '' }, status: status || 0, transport: true };
}

/**
 * @param {object} o {method, path, body, key(去重键), timeoutMs, confirm}
 */
export async function request(o) {
  const method = (o.method || 'GET').toUpperCase();
  const path = o.path;
  const url = `${PREFIX}${path}${qs(o.params)}`;
  const key = o.key || `${method}:${url}`;
  const timeoutMs = o.timeoutMs || (method === 'GET' ? 8000 : 12000);

  const prev = inflight.get(key);
  if (prev) prev.abort();
  const ctrl = new AbortController();
  inflight.set(key, ctrl);
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);

  const headers = { Accept: 'application/json' };
  if (method !== 'GET') {
    headers['X-CSRF-Token'] = csrfFor(method, path);
    headers['Content-Type'] = 'application/json';
  }
  let body;
  if (method !== 'GET' && o.body !== undefined) {
    body = JSON.stringify(o.body === null ? {} : { ...o.body });
  }

  try {
    const res = await fetch(url, {
      method,
      headers,
      body,
      credentials: 'same-origin',
      signal: ctrl.signal,
      // 面板接口一律 no-store, 这里再关一次缓存: 浏览器缓存里的旧快照会让人以为采集坏了。
      cache: 'no-store',
    });

    let payload = null;
    const ctype = res.headers.get('Content-Type') || '';
    if (ctype.indexOf('json') >= 0) {
      payload = await res.json().catch(() => null);
    } else {
      const t = await res.text();
      payload = { ok: false, error: { code: `http_${res.status}`, message: t.slice(0, 160), request_id: '' } };
    }

    if (!payload) {
      return failure('bad_json', '响应不是合法 JSON', res.status);
    }
    payload.status = res.status;
    if (res.status === 404 && !payload.error) {
      payload = failure('not_found', '接口不存在', 404);
    }
    if (!res.ok && payload.ok !== false) {
      payload.ok = false;
      payload.error = payload.error || { code: `http_${res.status}`, message: '请求失败', request_id: '' };
    }
    // 404 有两种来源: 会话失效(被统一伪装成 404)与真的没这个接口。前者要通知外壳掉出面板,
    // 否则用户会对着一个永不更新的界面反复点刷新。
    if (res.status === 404 || res.status === 401) {
      document.dispatchEvent(new CustomEvent('gha:auth-lost', { detail: { status: res.status } }));
    }
    if (res.status === 429) {
      document.dispatchEvent(new CustomEvent('gha:ratelimited', { detail: { retry: Number(res.headers.get('Retry-After') || 30) } }));
    }
    return payload;
  } catch (e) {
    const name = e && e.name;
    if (name === 'AbortError') {
      // 主动取消(被同类请求挤掉或超时)不是错误, 但调用方需要能区分, 于是不算失败次数。
      return failure('aborted', '请求已取消', 0);
    }
    return failure('network', String((e && e.message) || '网络错误'), 0);
  } finally {
    clearTimeout(timer);
    if (inflight.get(key) === ctrl) inflight.delete(key);
  }
}

export const get = (path, params, key) =>
  request({ method: 'GET', path, params, key });

/**
 * 写请求。
 *
 * confirm 只在这个入口拼装: 危险操作(purge all / 删源 / 吊销令牌 / 改配置 / 熔断复位)
 * 的 body 一定带 confirm:true, 而是否危险由调用方(即点击了带"二次确认"的按钮)决定 ——
 * 服务端还会再查一次, 前端这一层挡的是误点。
 */
export function write(method, path, body, opt) {
  const o = opt || {};
  const b = { ...(body || {}) };
  if (o.confirm) b.confirm = true;
  return request({
    method,
    path,
    body: b,
    key: o.key || `${method}:${path}`,
    timeoutMs: o.timeoutMs,
  });
}

/** 打断所有在飞的请求: 切视图与页面隐藏时用, 免得旧请求回来覆盖新视图的内容。 */
export function abortAll() {
  inflight.forEach((c) => c.abort());
  inflight.clear();
}

export { inflight };
