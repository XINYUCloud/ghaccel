/**
 * GhAccel — GitHub 访问/下载加速网关
 *
 * 本文件职责: 自研 SVG 图表。折线(请求/命中/失败)、分位数线、水平条(场景分布)、
 *             水位条(soft/hard/stop 三档)与迷你 sparkline。零依赖、不引 Chart.js/ECharts。
 *
 * @author    谶Hank
 * @copyright Copyright (c) 2026 谶Hank
 * @license   MIT https://opensource.org/licenses/MIT
 * @date      2026-11-05
 * @see       https://github.com/  完整版权与许可信息见仓库根目录 LICENSE
 */

/**
 * 三条实现纪律, 都是被面板的约束条件逼出来的:
 *
 *  1. 尺寸只从 CSS 自定义属性读(container 的 --w/--h 或布局盒), 绝不写内联 style 字符串。
 *     CSP 的 style-src 虽然允许 unsafe-inline, 但 script-src 一寸不让 —— 任何
 *     `el.setAttribute('style', ...)` 的拼串习惯都是同类漏洞的入口, 统一走 setProperty。
 *  2. 只用 createElementNS + textContent, 全程不碰 innerHTML: 图上的标签会带上源域名、
 *     ref 摘要与错误文案这些外部可控内容。
 *  3. 视图被隐藏时(clientWidth=0)不画, 只记一个 dirty 标记, 由调用方在切回该视图时重绘 ——
 *     否则会画出一张 0×0 的图并永久停在"看起来是空的"状态。
 */

const NS = 'http://www.w3.org/2000/svg';

const FONT = 'var(--sans)';

/** 创建 SVG 元素。属性值一律走 setAttribute, 文本一律走 textContent。 */
function el(name, attrs) {
  const n = document.createElementNS(NS, name);
  if (attrs) {
    for (const k of Object.keys(attrs)) {
      const v = attrs[k];
      if (v !== null && v !== undefined && v !== '') {
        n.setAttribute(k, String(v));
      }
    }
  }
  return n;
}

function text(content, attrs) {
  const t = el('text', attrs);
  t.textContent = String(content);
  return t;
}

/**
 * 取绘图可用尺寸。
 *
 * 用 getBoundingClientRect 而不是读 --w: --w 常常写的是 100%, 需要的是解析后的像素值,
 * 而 viewBox 必须是数字。返回 null 表示当前不可见(交给调用方标 dirty)。
 */
function box(boxEl) {
  const r = boxEl.getBoundingClientRect();
  const w = Math.round(r.width || 0);
  const h = Math.round(r.height || 0);
  if (w < 8 || h < 8) {
    return null;
  }
  return { w, h };
}

function mount(boxEl, draw) {
  boxEl.textContent = '';
  const size = box(boxEl);
  if (size === null) {
    boxEl.dataset.ghaDirty = '1';
    return false;
  }
  delete boxEl.dataset.ghaDirty;
  const svg = el('svg', {
    viewBox: `0 0 ${size.w} ${size.h}`,
    preserveAspectRatio: 'none',
    role: 'img',
    'aria-label': boxEl.dataset.label || '图表',
  });
  draw(svg, size.w, size.h);
  boxEl.appendChild(svg);
  return true;
}

/** 漂亮刻度: 在 [0, max] 上给 3-5 个整数级刻度。 */
function ticks(max, want) {
  if (!(max > 0)) {
    return { step: 1, top: 1, list: [0, 1] };
  }
  const raw = max / (want || 4);
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const norm = raw / mag;
  const step = (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10) * mag;
  const top = Math.ceil(max / step) * step;
  const list = [];
  for (let v = 0; v <= top + step / 1e6; v += step) {
    list.push(Number(v.toFixed(10)));
  }
  return { step, top, list };
}

function fmtNum(v, unit) {
  if (v === null || v === undefined || typeof v !== 'number' || Number.isNaN(v)) {
    return '—';
  }
  const a = Math.abs(v);
  let s;
  if (a >= 1073741824) s = (v / 1073741824).toFixed(2) + ' Gi';
  else if (a >= 1048576) s = (v / 1048576).toFixed(2) + ' M';
  else if (a >= 1024) s = (v / 1024).toFixed(1) + ' K';
  else if (a >= 100) s = v.toFixed(0);
  else if (a >= 10) s = v.toFixed(1);
  else s = v.toFixed(2);
  return s + (unit || '');
}

/** 整数计数专用: 不要和 fmtNum 的"缩写"语义混用, 否则条目数会显示成 "1.2 K"。 */
export function inum(v) {
  if (v === null || v === undefined || typeof v !== 'number' || Number.isNaN(v)) {
    return '—';
  }
  return Math.round(v).toLocaleString('en-US');
}

/**
 * 折线/面积图。series: [{name, cls, points:[num|null]}]
 *
 * null 是"这个桶没有样本", 不是 0 —— 把它连成 0 会让"夜间没人访问"显示成"性能断崖",
 * 这是运维最容易误读的一类图。所以这里按 null 断线。
 */
export function lineChart(boxEl, series, opts) {
  const o = opts || {};
  const pad = { l: o.padLeft ?? 46, r: o.padRight ?? 8, t: o.padTop ?? 8, b: o.padBottom ?? 18 };
  return mount(boxEl, (svg, W, H) => {
    const iw = Math.max(10, W - pad.l - pad.r);
    const ih = Math.max(10, H - pad.t - pad.b);
    let max = 0;
    let n = 0;
    for (const s of series) {
      const pts = s.points || [];
      n = Math.max(n, pts.length);
      for (const v of pts) {
        if (typeof v === 'number' && Number.isFinite(v) && v > max) max = v;
      }
    }
    if (o.max !== undefined && o.max > max) max = o.max;
    const t = ticks(max || 1, o.ticks || 4);
    const y = (v) => pad.t + ih - (v / t.top) * ih;
    const x = (i) => pad.l + (n <= 1 ? iw / 2 : (i / (n - 1)) * iw);

    const gAxis = el('g', { class: 'axis' });
    for (const tv of t.list) {
      gAxis.appendChild(el('line', { class: 'gridline', x1: pad.l, x2: pad.l + iw, y1: y(tv).toFixed(1), y2: y(tv).toFixed(1) }));
      gAxis.appendChild(text(fmtNum(tv, o.unit), { x: pad.l - 5, y: (y(tv) + 3).toFixed(1), 'text-anchor': 'end' }));
    }
    gAxis.appendChild(el('line', { x1: pad.l, x2: pad.l + iw, y1: (pad.t + ih).toFixed(1), y2: (pad.t + ih).toFixed(1) }));
    svg.appendChild(gAxis);

    // 阈值线: 熔断/水位这类"该在某个值以下"的指标没有参照线就等于没图。
    for (const th of o.thresholds || []) {
      if (typeof th.value !== 'number') continue;
      const yy = y(Math.min(th.value, t.top));
      const cls = 'thresh' + (th.cls ? ' ' + th.cls : '');
      svg.appendChild(el('line', { class: cls, x1: pad.l, x2: pad.l + iw, y1: yy.toFixed(1), y2: yy.toFixed(1) }));
      if (th.label) {
        svg.appendChild(text(th.label, { class: cls, x: pad.l + iw, y: (yy - 3).toFixed(1), 'text-anchor': 'end' }));
      }
    }

    for (const s of series) {
      const pts = s.points || [];
      if (!pts.length) continue;
      let d = '';
      let started = false;
      const segs = [];
      let cur = [];
      pts.forEach((v, i) => {
        if (typeof v !== 'number' || !Number.isFinite(v)) {
          if (cur.length) segs.push(cur);
          cur = [];
          return;
        }
        const px = x(i).toFixed(1);
        const py = y(Math.min(v, t.top)).toFixed(1);
        cur.push([px, py]);
        if (!started) {
          d += `M${px} ${py}`;
          started = true;
        } else {
          d += `L${px} ${py}`;
        }
      });
      if (cur.length) segs.push(cur);

      if (s.area && segs.length === 1 && started) {
        const first = d.match(/^M[\d.]+ [\d.]+/);
        if (first) {
          const lastPt = segs[0][segs[0].length - 1];
          const area = d
            + `L${lastPt[0]} ${(pad.t + ih).toFixed(1)}`
            + `L${first[0].slice(1).split(' ')[0]} ${(pad.t + ih).toFixed(1)}Z`;
          svg.appendChild(el('path', { class: 'series-area', d: area }));
        }
      }
      svg.appendChild(el('path', { class: 'series-line' + (s.cls ? ' ' + s.cls : ''), d }));
      if (s.dots) {
        for (const seg of segs) {
          for (const p of seg) {
            svg.appendChild(el('circle', { class: 'dot', cx: p[0], cy: p[1], r: 1.8 }));
          }
        }
      }
    }

    if (o.xlabel) {
      o.xlabel.forEach((lab, i) => {
        if (!lab) return;
        svg.appendChild(text(lab, { class: 'axis', x: x(i).toFixed(1), y: H - 4, 'text-anchor': 'middle' }));
      });
    }
  });
}

/** 定点小数: 延迟这类"不能被缩写成 K/M"的量必须用这个, 否则 1500ms 会显示成 1.5 K。 */
export function fixed(v, digits) {
  if (v === null || v === undefined || typeof v !== 'number' || Number.isNaN(v)) {
    return '—';
  }
  return v.toFixed(digits === undefined ? 1 : digits);
}

/** 迷你折线: 榜单每行一个, 只画趋势不画轴。 */
export function sparkline(boxEl, points, cls) {
  return mount(boxEl, (svg, W, H) => {
    const pts = (points || []).filter((v) => typeof v === 'number' && Number.isFinite(v));
    if (pts.length < 2) {
      svg.appendChild(text('样本不足', { class: 'axis', x: 2, y: H / 2 + 3 }));
      return;
    }
    let lo = Infinity;
    let hi = -Infinity;
    for (const v of pts) {
      if (v < lo) lo = v;
      if (v > hi) hi = v;
    }
    const span = hi - lo || 1;
    const d = pts
      .map((v, i) => `${i === 0 ? 'M' : 'L'}${((i / (pts.length - 1)) * (W - 2) + 1).toFixed(1)} ${(H - 2 - ((v - lo) / span) * (H - 4)).toFixed(1)}`)
      .join('');
    svg.appendChild(el('path', { class: 'series-line' + (cls ? ' ' + cls : ''), d, 'stroke-width': 1.2 }));
    svg.appendChild(text(fmtNum(hi), { class: 'axis', x: W - 1, y: 8, 'text-anchor': 'end' }));
    svg.appendChild(text(fmtNum(lo), { class: 'axis', x: W - 1, y: H - 1, 'text-anchor': 'end' }));
  });
}

/**
 * 容量水位条: 一根条 + soft/hard/stop 三道刻度。
 *
 * 三档必须同图可见, 因为"该不该慌"取决于当前处在哪个区间而不是绝对用量:
 * 70% 是后台慢慢淘汰, 85% 是写前同步淘汰(会加延迟), 95% 是停写(命中率开始掉)。
 */
export function watermarkBar(boxEl, o) {
  return mount(boxEl, (svg, W, H) => {
    const ratio = Math.max(0, Math.min(1, Number(o.ratio) || 0));
    const h = Math.max(8, Math.min(16, H - 4));
    const y = (H - h) / 2;
    svg.appendChild(el('rect', { x: 0, y, width: W, height: h, rx: 3, class: 'bar-track-rect', fill: 'var(--bar-track)' }));
    const cls = ratio >= (o.stop ?? 0.95) ? 'stop' : ratio >= (o.hard ?? 0.85) ? 'hard' : ratio >= (o.soft ?? 0.7) ? 'soft' : '';
    svg.appendChild(el('rect', { x: 0, y, width: (W * ratio).toFixed(1), height: h, rx: 3, class: 'water-' + (cls || 'soft'), fill: cls === 'stop' ? 'var(--bad)' : cls === 'hard' ? 'var(--warn)' : cls === 'soft' ? 'var(--warn)' : 'var(--ok)' }));
    for (const [key, val] of [['soft', o.soft], ['hard', o.hard], ['stop', o.stop]]) {
      if (typeof val !== 'number') continue;
      const x = (W * Math.max(0, Math.min(1, val))).toFixed(1);
      svg.appendChild(el('line', { class: 'thresh ' + key, x1: x, x2: x, y1: y - 3, y2: y + h + 3 }));
      svg.appendChild(text(key, { class: 'thresh ' + key, x, y: y - 5, 'text-anchor': 'middle' }));
    }
    svg.appendChild(text(`${(ratio * 100).toFixed(1)}%`, { x: 3, y: y + h / 2 + 4, class: 'water-label', fill: 'var(--fg)' }));
  });
}

/** 水平条: 场景分布、因子贡献这类"多项比大小"。rows=[{label,value,sub}] */
export function hBars(boxEl, rows, opts) {
  const o = opts || {};
  return mount(boxEl, (svg, W, H) => {
    const list = rows || [];
    if (!list.length) {
      svg.appendChild(text(o.emptyText || '无数据', { class: 'axis', x: 2, y: H / 2 + 3 }));
      return;
    }
    const labelW = o.labelWidth ?? Math.min(150, Math.max(70, W * 0.34));
    const rowH = Math.max(14, Math.min(26, Math.floor(H / list.length)));
    const barH = Math.max(7, rowH - 8);
    let max = 0;
    for (const r of list) {
      const v = Number(r.value) || 0;
      if (v > max) max = v;
    }
    max = max || 1;
    list.forEach((r, i) => {
      const yy = i * rowH;
      svg.appendChild(text(String(r.label ?? ''), { class: 'axis', x: 0, y: yy + rowH / 2 + 1, 'text-anchor': 'start' }));
      const bw = ((Number(r.value) || 0) / max) * Math.max(6, W - labelW - 60);
      svg.appendChild(el('rect', {
        x: labelW, y: yy + 3, width: bw.toFixed(1), height: barH, rx: 2,
        fill: r.cls === 'bad' ? 'var(--bad)' : r.cls === 'warn' ? 'var(--warn)' : 'var(--accent)',
      }));
      svg.appendChild(text(String(r.sub ?? fmtNum(Number(r.value) || 0, o.unit)), {
        class: 'axis', x: labelW + bw + 5, y: yy + rowH / 2 + 1, 'text-anchor': 'start',
      }));
    });
  });
}

/**
 * 因子贡献条: 决策视图的"权重 × 归一值 = 贡献"必须能画出来并且相加等于总分,
 * 所以这里把每段的宽度直接按贡献占比给, 顶部标总分。
 */
export function contributionBar(boxEl, factors, total) {
  return mount(boxEl, (svg, W, H) => {
    const items = factors || [];
    const sum = items.reduce((a, f) => a + (Number(f.contrib) || 0), 0);
    const h = Math.max(9, Math.min(16, H - 6));
    const y = (H - h) / 2;
    svg.appendChild(el('rect', { x: 0, y, width: W, height: h, rx: 2, fill: 'var(--bar-track)' }));
    const palette = ['var(--accent)', 'var(--ok)', 'var(--warn)', 'var(--idle)', 'var(--bad)'];
    let x = 0;
    items.forEach((f, i) => {
      const w = sum > 0 ? ((Number(f.contrib) || 0) / sum) * W : 0;
      svg.appendChild(el('rect', { x: x.toFixed(1), y, width: Math.max(0, w).toFixed(1), height: h, fill: palette[i % palette.length], opacity: 0.85 }));
      if (w > 22) {
        svg.appendChild(text(String(f.label || ''), { class: 'axis', x: (x + w / 2).toFixed(1), y: y + h / 2 + 3, 'text-anchor': 'middle', fill: '#fff' }));
      }
      x += w;
    });
    svg.appendChild(text(`Σ=${(Math.round(sum * 1e6) / 1e6).toFixed(6)} · score=${(Math.round((Number(total) || 0) * 1e6) / 1e6).toFixed(6)}`, {
      class: 'axis', x: W, y: H - 1, 'text-anchor': 'end',
    }));
  });
}

/** 视图切回来时补画之前因隐藏而跳过的图。 */
export function redrawDirty(root) {
  const boxes = (root || document).querySelectorAll('.chartbox[data-gha-dirty="1"]');
  const out = [];
  boxes.forEach((b) => {
    if (b.dataset.ghaRedraw) {
      out.push(b);
    }
  });
  return out;
}

export { fmtNum, ticks };
