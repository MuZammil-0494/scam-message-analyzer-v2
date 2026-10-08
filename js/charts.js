/* ============================================================================
 * charts.js — Tiny dependency-free charts (SVG + divs). No canvas, no libs,
 * so it works offline and is easy to style for both themes.
 * ==========================================================================*/
(function (g) {
  'use strict';
  var SCAM = (g.SCAM = g.SCAM || {});
  var LEVEL_COLORS = {
    safe: '#2E7D51', low: '#8A6D1F', medium: '#A85D14', high: '#B23B2E', critical: '#8E1F1B'
  };

  /* Vertical bar chart from [ { label, value, color } ] */
  function barChart(el, data, opts) {
    opts = opts || {};
    el.innerHTML = '';
    if (!data.length) { el.innerHTML = '<p class="fine">–</p>'; return; }
    var max = Math.max.apply(null, data.map(function (d) { return d.value; })) || 1;
    var wrap = document.createElement('div');
    wrap.className = 'bars';
    data.forEach(function (d) {
      var col = document.createElement('div');
      col.className = 'bar-col';
      col.title = d.label + ': ' + d.value;
      var val = document.createElement('span');
      val.className = 'bar-val';
      val.textContent = d.value;
      var bar = document.createElement('div');
      bar.className = 'bar';
      bar.style.height = String(Math.max(6, Math.round((d.value / max) * 100))) + '%';
      bar.style.background = d.color || LEVEL_COLORS.safe;
      var lab = document.createElement('span');
      lab.className = 'bar-label';
      lab.textContent = opts.short ? d.label.slice(0, opts.short) : d.label;
      col.appendChild(val);
      col.appendChild(bar);
      col.appendChild(lab);
      wrap.appendChild(col);
    });
    el.appendChild(wrap);
  }

  /* Rounded horizontal bars for attack counts */
  function hbar(el, data) {
    el.innerHTML = '';
    if (!data.length) { el.innerHTML = '<p class="fine">–</p>'; return; }
    var max = Math.max.apply(null, data.map(function (d) { return d.value; })) || 1;
    data.forEach(function (d) {
      var row = document.createElement('div');
      row.className = 'hbar-row';
      var lab = document.createElement('span');
      lab.className = 'hbar-label';
      lab.textContent = d.label;
      var track = document.createElement('div');
      track.className = 'hbar-track';
      var fill = document.createElement('div');
      fill.className = 'hbar-fill';
      fill.style.width = String(Math.max(8, Math.round((d.value / max) * 100))) + '%';
      fill.textContent = d.value;
      track.appendChild(fill);
      row.appendChild(lab);
      row.appendChild(track);
      el.appendChild(row);
    });
  }

  /* Timeline: columns of dots/bars ordered by time. Oldest on the left. */
  function timeline(el, items) {
    el.innerHTML = '';
    if (!items.length) { el.innerHTML = '<p class="fine">–</p>'; return; }
    var wrap = document.createElement('div');
    wrap.className = 'timeline';
    items.forEach(function (it) {
      var col = document.createElement('div');
      col.className = 'tl-col';
      col.title = it.level + ' — ' + it.score + '/100';
      var bar = document.createElement('div');
      bar.className = 'tl-bar';
      var h = Math.max(8, Math.round((it.score / 100) * 100));
      bar.style.height = h + 'px';
      bar.style.background = LEVEL_COLORS[it.level] || '#555';
      bar.style.opacity = '0.85';
      col.appendChild(bar);
      wrap.appendChild(col);
    });
    el.appendChild(wrap);
  }

  /* Semicircular risk gauge (SVG) */
  function gauge(svg, score, color) {
    svg.innerHTML = '';
    var ns = 'http://www.w3.org/2000/svg';
    var size = 200, cx = 100, cy = 100, r = 78, circ = Math.PI * r;
    svg.setAttribute('viewBox', '0 0 200 200');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Risk score ' + score + ' out of 100');

    function arc(path, frac, col) {
      var len = circ * frac;
      var off = len; /* dashoffset shows remaining first */
      var p = document.createElementNS(ns, 'path');
      p.setAttribute('d', 'M ' + (cx - r) + ' ' + (cy) +
        ' A ' + r + ' ' + r + ' 0 0 1 ' + (cx + r) + ' ' + cy);
      p.setAttribute('fill', 'none');
      p.setAttribute('stroke', col);
      p.setAttribute('stroke-width', '16');
      p.setAttribute('stroke-linecap', 'round');
      p.setAttribute('stroke-dasharray', len + ' ' + circ);
      p.setAttribute('stroke-dashoffset', circ - off);
      p.style.transition = 'stroke-dasharray 0.8s ease';
      path.appendChild(p);
      return p;
    }

    var track = document.createElementNS(ns, 'path');
    track.setAttribute('d', 'M ' + (cx - r) + ' ' + (cy) + ' A ' + r + ' ' + r + ' 0 0 1 ' + (cx + r) + ' ' + cy);
    track.setAttribute('fill', 'none');
    track.setAttribute('stroke', 'rgba(127,127,127,0.22)');
    track.setAttribute('stroke-width', '16');
    track.setAttribute('stroke-linecap', 'round');
    svg.appendChild(track);

    var grp = document.createElementNS(ns, 'g');
    svg.appendChild(grp);
    setTimeout(function () { arc(grp, score / 100, color); }, 60);

    var big = document.createElementNS(ns, 'text');
    big.setAttribute('x', '100'); big.setAttribute('y', '104');
    big.setAttribute('text-anchor', 'middle');
    big.setAttribute('class', 'gauge-num');
    big.textContent = score;
    big.setAttribute('dy', '0.35em');

    var sub = document.createElementNS(ns, 'text');
    sub.setAttribute('x', '100'); sub.setAttribute('y', '138');
    sub.setAttribute('text-anchor', 'middle');
    sub.setAttribute('class', 'gauge-out');
    sub.textContent = '/ 100';
    svg.appendChild(big);
    svg.appendChild(sub);
    return svg;
  }

  SCAM.Charts = { barChart: barChart, hbar: hbar, timeline: timeline, gauge: gauge, LEVEL_COLORS: LEVEL_COLORS };
})(typeof globalThis !== 'undefined' ? globalThis : this);