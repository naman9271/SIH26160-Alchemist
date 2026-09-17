import test from "node:test";
import assert from "node:assert/strict";
import { parseCSV } from "../app/labs/csv.ts";
test("capture metadata preserves JSON commas, escaped quotes and multiline values",()=>{
 assert.deepEqual(parseCSV('sample_id,generator_parameters,note\r\ns1,"{""seed"":1,""duration_s"":20}","first\nsecond"\r\n'),[
  ["sample_id","generator_parameters","note"],
  ["s1",'{"seed":1,"duration_s":20}',"first\nsecond"],
 ]);
});
test("incomplete CSV is rejected",()=>assert.throws(()=>parseCSV('id,note\ns1,"unfinished'),/unfinished/));
