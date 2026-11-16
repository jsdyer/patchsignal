import { cveOf, matchRows, probabilities, advisoryLink } from './model.mjs';

const $ = id => document.getElementById(id);
const form = $('lookup'), input = form.elements.query;
const percent = new Intl.NumberFormat('en-CA', { style:'percent', maximumFractionDigits:2 });
const count = new Intl.NumberFormat('en-CA');
const pageSize = 25;
let snapshot, catalogueError, state, activeID, currentPage = 0;
const localData = fetch('./kev.json', { signal: AbortSignal.timeout(15000) }).then(async r => {
  if (!r.ok) throw new Error('KEV index unavailable');
  const json = await r.json();
  if (!Array.isArray(json.rows) || !json.rows.length) throw new Error('KEV index is missing rows');
  snapshot = json;
  $('catalogue-count').textContent = count.format(json.rows.length) + ' CVEs';
  $('sources-date').textContent = 'CISA snapshot ' + json.kevDate.slice(0,10) + ' · ' + (json.epssDate ? 'EPSS snapshot ' + json.epssDate : 'EPSS snapshot unavailable');
}).catch(() => {
  catalogueError = true;
  $('catalogue-count').textContent = 'Unavailable';
}).finally(() => {
  renderBrowse();
  if (activeID) fillEvidence(activeID);
});

function node(tag, content, className) {
  const el = document.createElement(tag);
  if (content !== undefined) el.textContent = content;
  if (className) el.className = className;
  return el;
}

function link(text, href) {
  const a = node('a', text);
  a.href = href;
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  return a;
}

function status(text, error = false) {
  $('lookup-status').textContent = text;
  $('lookup-status').dataset.error = String(error);
}

function fillEvidence(id) {
  const row = snapshot?.rows.find(r => r.id === id);
  const text = row ? 'Listed in CISA KEV' : snapshot ? 'Outside this KEV snapshot' : 'KEV membership unavailable';
  $('kev-status').textContent = text;
  $('kev-status').classList.toggle('warn', !!row);
  $('cisa-evidence').textContent = row
    ? 'Added ' + row.added + ' · CISA due date ' + row.due + ' · ransomware use ' + (row.ransomware || 'unspecified')
    : snapshot ? 'Catalogue snapshot ' + snapshot.kevDate.slice(0,10) + '. Exploitation may still occur outside the catalogue.' : 'Check the official CISA catalogue for membership.';
  $('cisa-action').textContent = row?.action || '';
}

async function request(url, signal) {
  const response = await fetch(url, {signal: AbortSignal.any([signal, AbortSignal.timeout(16000)]), credentials:'omit'});
  if (!response.ok) throw new Error('HTTP ' + response.status);
  return response.json();
}

function fillRecord(cve, row, code) {
  const cna = cve?.containers?.cna;
  if (cve?.cveMetadata?.cveId !== code) throw new Error('Unexpected CVE record');
  const descriptions = Array.isArray(cna?.descriptions) ? cna.descriptions : cna?.rejectedReasons || [];
  const description = descriptions.find(d => d.lang?.startsWith('en')) || descriptions[0];
  $('cve-title').textContent = cna?.title || row?.name || '';
  $('cve-title').hidden = !$('cve-title').textContent;
  $('description').textContent = cve.cveMetadata.state === 'REJECTED'
    ? 'CVE Program state: REJECTED. ' + (description?.value || '')
    : description?.value || row?.description || 'The CVE Program did not include a description.';
  const products = (Array.isArray(cna?.affected) ? cna.affected : []).slice(0,20).map(info => {
    const versions = (Array.isArray(info.versions) ? info.versions : []).filter(v=>v.status==='affected').slice(0,5).map(v => [
      v.version, v.lessThan ? 'to before ' + v.lessThan : v.lessThanOrEqual ? 'through ' + v.lessThanOrEqual : ''
    ].filter(Boolean).join(' '));
    return node('li', [info.vendor, info.product || info.packageName, versions.join(', ')].filter(Boolean).join(' · ') || 'Product details unspecified');
  });
  const refs = (Array.isArray(cna?.references) ? cna.references : []).slice(0,16).flatMap(ref => {
    const href = advisoryLink(ref.url);
    if (!href) return [];
    const li = node('li');
    li.append(link(ref.name || new URL(href).hostname + ' ↗', href));
    if (ref.tags?.length) li.append(' · ' + ref.tags.join(', '));
    return [li];
  });
  $('products').replaceChildren(...products);
  $('references').replaceChildren(...refs);
  $('affected').hidden = !products.length && !refs.length;
}

function chart(points) {
  const canvas = $('chart');
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  const left = 51, right = canvas.width - 16, top = 14, height = 151;
  const first = Date.parse(points[0].day), last = Date.parse(points.at(-1).day);
  const x = day => left + (right - left) * (Date.parse(day) - first) / ((last - first) || 1);
  const y = score => top + height * (1 - score);
  ctx.clearRect(0,0,canvas.width,canvas.height);
  ctx.font = '12px monospace';
  ctx.fillStyle = '#354738';
  for (const p of [0,.25,.50,.75,1]) {
    ctx.fillText(percent.format(p), 5, y(p) + 4);
    ctx.strokeStyle = '#d0d9c7';
    ctx.beginPath(); ctx.moveTo(left,y(p)); ctx.lineTo(right,y(p)); ctx.stroke();
  }
  ctx.strokeStyle = '#2b6646';
  ctx.lineWidth = 3;
  ctx.beginPath();
  for (let i=0; i<points.length; i++) {
    const pt = points[i];
    if (i && Date.parse(pt.day) - Date.parse(points[i-1].day) <= 86400000) ctx.lineTo(x(pt.day), y(pt.score));
    else ctx.moveTo(x(pt.day), y(pt.score));
  }
  ctx.stroke();
  for (const pt of points) {
    ctx.beginPath(); ctx.arc(x(pt.day),y(pt.score),2.6,0,Math.PI*2); ctx.fill();
  }
  ctx.lineWidth = 1;
  ctx.fillText(points[0].day,left,188);
  if (points.length > 1) ctx.fillText(points.at(-1).day,right-76,188);
}

function fillEpss(data, code) {
  const points = probabilities(data, code);
  const last = points.at(-1);
  $('epss-summary').textContent = last ? percent.format(last.score) + ' probability · ' + percent.format(last.percentile) + ' percentile · ' + last.day : 'FIRST did not return an EPSS score for this CVE.';
  $('history').replaceChildren(...[...points].reverse().map(pt => {
    const row = node('tr');
    row.append(node('td',pt.day),node('td',percent.format(pt.score)),node('td',percent.format(pt.percentile)));
    return row;
  }));
  $('trend').hidden = !last;
  if (last) chart(points);
}

async function lookup(value) {
  const code = cveOf(value);
  if (!code) { status('Enter a CVE like CVE-2021-44228 or a known nickname such as Log4Shell. Search product names in the catalogue below.', true); return; }
  state?.abort();
  state = new AbortController();
  const task = state;
  input.value = code;
  activeID = code;
  history.replaceState(null, '', '#' + new URLSearchParams({ cve: code }));
  $('detail').hidden = false;
  for (const id of ['trend', 'affected', 'cve-title']) $(id).hidden = true;
  $('cve-id').textContent = code;
  $('description').textContent = 'Loading CVE record…';
  $('epss-summary').textContent = 'Loading FIRST EPSS scores…';
  $('record-links').replaceChildren(link('Official CVE record ↗','https://www.cve.org/CVERecord?id=' + code),link('CISA catalogue ↗','https://www.cisa.gov/known-exploited-vulnerabilities-catalog'));
  fillEvidence(code);
  status('Checking the CVE Program and FIRST EPSS…');
  const [cve, epss] = await Promise.allSettled([
    request('https://cveawg.mitre.org/api/cve/' + code, task.signal),
    request('https://api.first.org/data/v1/epss?' + new URLSearchParams({cve:code,scope:'time-series'}), task.signal),
    localData,
  ]);
  if (task.signal.aborted) return;
  const row = snapshot?.rows.find(r=>r.id===code);
  try {
    if (cve.status === 'rejected') throw cve.reason;
    fillRecord(cve.value, row, code);
  } catch {
    $('description').textContent = row ? 'CVE Program lookup unavailable. CISA summary: ' + row.description : 'CVE Program lookup unavailable or the record is unpublished. Open the official CVE page to check its status.';
  }
  try {
    if (epss.status === 'rejected') throw epss.reason;
    fillEpss(epss.value, code);
  } catch {
    $('epss-summary').textContent = row?.score ? 'Live scores unavailable · snapshot estimate ' + percent.format(row.score[0]) + ' · ' + snapshot.epssDate : 'Live FIRST EPSS scores unavailable.';
  }
  status('Sources checked. See each panel for coverage.');
}

function renderBrowse() {
  const status = $('browse-status');
  if (!snapshot) {
    status.textContent = catalogueError ? 'Catalogue unavailable. Exact CVE lookup remains available above.' : 'Loading the local CISA catalogue…';
    return;
  }
  const filtered = matchRows(snapshot.rows, $('filter').value, $('priority').value);
  const pages = Math.ceil(filtered.length / pageSize);
  currentPage = Math.min(currentPage, Math.max(0, pages - 1));
  const shown = filtered.slice(currentPage * pageSize, (currentPage + 1) * pageSize);
  status.textContent = shown.length ? count.format(filtered.length) + ' matching KEV entries' : 'No matches in this KEV snapshot. Try a broader product search or a direct CVE lookup.';
  $('rows').replaceChildren(...shown.map(row => {
    const tr = node('tr');
    const button = node('button',row.id);
    button.addEventListener('click',()=>{ lookup(row.id); $('lookup-title').scrollIntoView({block:'start'}); input.focus({preventScroll:true}); });
    const name = node('td');
    name.append(button,node('span',row.vendor + ' · ' + row.product,'vendor'));
    tr.append(name,node('td',row.score ? percent.format(row.score[0]) : 'Unavailable'),node('td',row.added));
    return tr;
  }));
  $('browse-table').hidden = !shown.length;
  $('pagination').hidden = pages < 2;
  $('page').textContent = 'Page ' + (currentPage + 1) + ' of ' + pages;
  $('previous').disabled = currentPage === 0;
  $('next').disabled = currentPage + 1 >= pages;
}
form.addEventListener('submit',event=>{event.preventDefault();lookup(input.value);});
document.querySelectorAll('[data-cve]').forEach(b=>b.addEventListener('click',()=>lookup(b.dataset.cve)));
for (const id of ['filter','priority']) $(id).addEventListener('input',()=>{currentPage=0;renderBrowse();});
$('previous').addEventListener('click',()=>{if(currentPage){currentPage--;renderBrowse();}});
$('next').addEventListener('click',()=>{currentPage++;renderBrowse();});
const shared = new URLSearchParams(location.hash.slice(1)).get('cve');
if (shared && cveOf(shared)) input.value = cveOf(shared);
