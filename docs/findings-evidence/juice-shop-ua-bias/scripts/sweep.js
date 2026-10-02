const path='/Users/diego/Uvg/Proyecto de Graduacion/logSguarDian/';
const { extractFeatureVector, FEATURE_NAMES } = require(path+'packages/extractor/dist/index.js');
const ort = require(path+'packages/core/node_modules/onnxruntime-node');
const EX = new Set(['status_code','req_count_1s','req_count_5s','req_count_60s','error_rate_4xx_60s','endpoint_diversity_60s','non_json_quote_count']);
const names=FEATURE_NAMES.filter(n=>!EX.has(n));
let s;
const mv=r=>extractFeatureVector(r).filter((_,i)=>!EX.has(FEATURE_NAMES[i]));
async function sqli(vec){const t=new ort.Tensor('float32',Float32Array.from(vec),[1,vec.length]);const r=await s.run({[s.inputNames[0]]:t});return r[s.outputNames[1]].data;}
(async()=>{
 s=await ort.InferenceSession.create(path+'training/models/rf.onnx');
 for (const ua of ['curl/8.7.1','Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120 Safari/537.36']) {
  const base={method:'GET',userAgent:ua,contentType:'',referer:'',cookie:'',extraHeaders:{},body:''};
  console.log('\nUA:',ua.slice(0,12));
  console.log('A) sweep path_length(+uri_length) only on juice vector, q=apple, depth fixed 3');
  const v=mv({...base,path:'/rest/products/search',query:'q=apple'});
  const ip=names.indexOf('path_length'), iu=names.indexOf('uri_length');
  const row=[];
  for(let L=10;L<=30;L+=2){const w=[...v];w[iu]=v[iu]-v[ip]+L;w[ip]=L;const p=await sqli(w);row.push(`${L}:${p[3].toFixed(2)}`);}
  console.log(row.join('  '));
  console.log('B) real paths, 2 segments (/aaa/bbb...), q=apple');
  const rb=[];for(let L=10;L<=30;L+=2){const a='a'.repeat(Math.floor((L-2)/2)),b='b'.repeat(L-2-a.length);const pth='/'+a+'/'+b;const p=await sqli(mv({...base,path:pth,query:'q=apple'}));rb.push(`${pth.length}:${p[3].toFixed(2)}`);}
  console.log(rb.join('  '));
  console.log('C) real paths, 3 segments');
  const rc=[];for(let L=10;L<=30;L+=2){const k=Math.floor((L-3)/3);const pth='/'+'a'.repeat(k)+'/'+'b'.repeat(k)+'/'+'c'.repeat(L-3-2*k);const p=await sqli(mv({...base,path:pth,query:'q=apple'}));rc.push(`${pth.length}:${p[3].toFixed(2)}`);}
  console.log(rc.join('  '));
  console.log('D) control: Juice path, no "=" (q-less)  sqli prob', (await sqli(mv({...base,path:'/rest/products/search',query:''})))[3].toFixed(2));
 }
})();
