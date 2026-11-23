export function inventoryMatches(text,rows){
 const ids=[...new Set((text.toUpperCase().match(/\bCVE-\d{4}-\d{4,19}\b/g)||[]))];
 if(!ids.length)throw Error('Paste CVE identifiers, for example CVE-2021-44228.');
 if(ids.length>250)throw Error('Compare up to 250 distinct CVEs at once.');
 const index=new Map(rows.map(row=>[row.id,row]));
 return ids.map(id=>({id,kev:index.get(id)||null})).sort((a,b)=>Number(!!b.kev)-Number(!!a.kev)||a.id.localeCompare(b.id));
}
