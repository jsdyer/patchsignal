const alias = {
  log4shell: 'CVE-2021-44228',
  heartbleed: 'CVE-2014-0160',
  eternalblue: 'CVE-2017-0144',
  shellshock: 'CVE-2014-6271',
  bluekeep: 'CVE-2019-0708',
  printnightmare: 'CVE-2021-34527',
  xz: 'CVE-2024-3094',
};

function compact(value) {
  return String(value ?? '').toLowerCase().replace(/[^a-z\d]/g, '');
}

export function cveOf(value) {
  const raw = String(value ?? '').trim().toUpperCase();
  if (/^CVE-\d{4}-\d{4,19}$/.test(raw)) return raw;
  const key = compact(raw);
  return Object.hasOwn(alias, key) ? alias[key] : null;
}

export function matchRows(rows, term, view) {
  const id = cveOf(term);
  const tokens = term.toLowerCase().trim().split(/\s+/).filter(Boolean);
  return rows.filter(row => {
    if (view === 'watch' && !(row.score?.[0] >= .10)) return false;
    if (view === 'ransom' && row.ransomware !== 'Known') return false;
    if (id) return row.id === id;
    const hay = [row.id, row.vendor, row.product, row.name, ...Object.keys(alias).filter(a => alias[a] === row.id)].join(' ').toLowerCase();
    return tokens.every(token => hay.includes(token));
  }).sort((a, b) => (
    view === 'score' || view === 'watch' ? (b.score?.[0] ?? -1) - (a.score?.[0] ?? -1) : 0
  ) || b.added.localeCompare(a.added) || a.id.localeCompare(b.id));
}

export function probabilities(body, id) {
  if (body?.status !== 'OK' || !Array.isArray(body.data)) throw new Error('Unexpected EPSS response');
  const record = body.data.find(item => item.cve === id);
  if (!record) return [];
  const byDay = new Map();
  const earlier = Array.isArray(record['time-series']) ? record['time-series'] : [];
  for (const item of [...earlier, record]) {
    if (!item || !/^\d{4}-\d\d-\d\d$/.test(item.date) || item.epss == null || item.percentile == null) continue;
    const score = Number(item.epss), percentile = Number(item.percentile);
    if (score >= 0 && score <= 1 && percentile >= 0 && percentile <= 1) byDay.set(item.date, { day: item.date, score, percentile });
  }
  return [...byDay.values()].sort((a,b) => a.day.localeCompare(b.day));
}

export function advisoryLink(url) {
  try {
    const u = new URL(url);
    return ['http:', 'https:'].includes(u.protocol) && !u.username && !u.password ? u.href : null;
  } catch { return null; }
}
