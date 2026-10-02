const path='/Users/diego/Uvg/Proyecto de Graduacion/logSguarDian/';
const { extractFeatureVector, FEATURE_NAMES } = require(path+'packages/extractor/dist/index.js');
const ort = require(path+'packages/core/node_modules/onnxruntime-node');
const EX = new Set(['status_code','req_count_1s','req_count_5s','req_count_60s','error_rate_4xx_60s','endpoint_diversity_60s','non_json_quote_count']);
const classes=['benign','cmdi','path_traversal','sqli','xss'];
const names=FEATURE_NAMES.filter(n=>!EX.has(n));
let s;
async function p(vec){const t=new ort.Tensor('float32',Float32Array.from(vec),[1,vec.length]);const r=await s.run({[s.inputNames[0]]:t});const x=r[s.outputNames[1]].data;return classes.map((c,i)=>c[0]+c.slice(1,3)+'='+x[i].toFixed(2)).join(' ');}
const mv=r=>extractFeatureVector(r).filter((_,i)=>!EX.has(FEATURE_NAMES[i]));
(async()=>{
 s=await ort.InferenceSession.create(path+'training/models/rf.onnx');
 const base={method:'GET',userAgent:'curl/8.7.1',contentType:'',referer:'',cookie:'',extraHeaders:{},body:''};
 const v=mv({...base,path:'/rest/products/search',query:'q=apple'});
 console.log('baseline            ',await p(v));
 for(const f of ['sqli_operator_count','ua_suspicious','path_depth','path_length','uri_length','special_char_ratio']){
   const w=[...v]; const i=names.indexOf(f); const orig=w[i]; w[i]= f==='path_depth'?2: f==='path_length'?13: f==='uri_length'?21: 0;
   console.log(('ablate '+f+' '+orig+'->'+w[i]).padEnd(46),await p(w));
 }
 const w=[...v]; w[names.indexOf('path_depth')]=2; w[names.indexOf('path_length')]=13; w[names.indexOf('uri_length')]=21;
 console.log('path shape of /posts/search'.padEnd(46),await p(w));
 for(const [lbl,path_,q] of [['/posts/products/search','/posts/products/search','q=apple'],['/api/v1/items/search','/api/v1/items/search','q=apple'],['/a/b/c','/a/b/c','q=apple']])
   console.log(lbl.padEnd(46),await p(mv({...base,path:path_,query:q})));
 const br={...base,userAgent:'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120 Safari/537.36',referer:'http://localhost:3001/',extraHeaders:{accept:'application/json'}};
 console.log('browser UA, juice path'.padEnd(46),await p(mv({...br,path:'/rest/products/search',query:'q=apple'})));
 console.log('browser UA, /posts/search'.padEnd(46),await p(mv({...br,path:'/posts/search',query:'q=apple'})));
})();
