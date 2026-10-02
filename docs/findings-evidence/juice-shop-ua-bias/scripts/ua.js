const path='/Users/diego/Uvg/Proyecto de Graduacion/logSguarDian/';
const { extractFeatureVector, FEATURE_NAMES } = require(path+'packages/extractor/dist/index.js');
const ort = require(path+'packages/core/node_modules/onnxruntime-node');
const EX = new Set(['status_code','req_count_1s','req_count_5s','req_count_60s','error_rate_4xx_60s','endpoint_diversity_60s','non_json_quote_count']);
const names=FEATURE_NAMES.filter(n=>!EX.has(n));
const mv=r=>extractFeatureVector(r).filter((_,i)=>!EX.has(FEATURE_NAMES[i]));
(async()=>{
 const s=await ort.InferenceSession.create(path+'training/models/rf.onnx');
 const UA='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120 Safari/537.36';
 const cases={
  'curl, no extras':{userAgent:'curl/8.7.1',referer:'',extraHeaders:{}},
  'browser UA only':{userAgent:UA,referer:'',extraHeaders:{}},
  'browser UA + referer':{userAgent:UA,referer:'http://localhost:3001/',extraHeaders:{}},
  'browser UA + accept':{userAgent:UA,referer:'',extraHeaders:{accept:'application/json'}},
  'browser UA + referer + accept':{userAgent:UA,referer:'http://localhost:3001/',extraHeaders:{accept:'application/json'}},
 };
 for(const pth of ['/posts/search','/rest/products/search']) for(const [k,c] of Object.entries(cases)){
  const v=mv({method:'GET',contentType:'',cookie:'',body:'',path:pth,query:'q=apple',...c});
  const t=new ort.Tensor('float32',Float32Array.from(v),[1,v.length]);const r=await s.run({[s.inputNames[0]]:t});const p=r[s.outputNames[1]].data;
  console.log(pth.padEnd(22),k.padEnd(30),'sqli',p[3].toFixed(2),'ben',p[0].toFixed(2));
 }
 const v=mv({method:'GET',contentType:'',cookie:'',body:'',path:'/posts/search',query:'q=apple',userAgent:UA,referer:'',extraHeaders:{}});
 console.log(names.map((n,i)=>[n,v[i]]).filter(([,x])=>x!==0).map(([n,x])=>n+'='+x).join(' '));
})();
