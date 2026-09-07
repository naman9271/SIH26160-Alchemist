import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
const code=ts.transpileModule(readFileSync(new URL('../components/dashboard/history-store.ts',import.meta.url),'utf8'),{compilerOptions:{module:ts.ModuleKind.ES2022}}).outputText;
const {readHistory,saveSnapshot}=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
test('history preserves snapshots and original chronology when an old report is reopened',()=>{
 const values=new Map();
 globalThis.localStorage={getItem:key=>values.get(key),setItem:(key,value)=>values.set(key,value)};
 globalThis.window={dispatchEvent:()=>{}};
 saveSnapshot('old',{analysis:{created_at:'2026-01-01T00:00:00Z'},security:{assessment:{score:70}}});
 saveSnapshot('new',{analysis:{created_at:'2026-01-02T00:00:00Z'},security:{assessment:{score:90}}});
 saveSnapshot('old',{analysis:{created_at:'2026-01-01T00:00:00Z'},security:{assessment:{score:71}}});
 assert.deepEqual(readHistory().map(v=>v.id),['new','old']);
 assert.equal(readHistory()[1].data.security.assessment.score,71);
 values.set('alchemist.analysis-history.v1','invalid JSON');
 assert.deepEqual(readHistory(),[]);
});
