import test from 'node:test';import assert from 'node:assert/strict';
import {inventoryMatches} from '../web/inventory.mjs';
test('deduplicates identifiers in mixed text and distinguishes unlisted from known exploited',()=>{
 const row={id:'CVE-2021-44228',vendor:'Apache'};
 const result=inventoryMatches('log: cve-2021-44228, CVE-2021-44228 and CVE-2099-9999',[row]);
 assert.deepEqual(result,[{id:row.id,kev:row},{id:'CVE-2099-9999',kev:null}]);
 assert.throws(()=>inventoryMatches('nothing',[]));
});
