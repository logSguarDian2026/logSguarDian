const fs=require('fs'),rl=require('readline');
const path='/Users/diego/Uvg/Proyecto de Graduacion/logSguarDian/';
const { extractFeatureVector, FEATURE_NAMES } = require(path+'packages/extractor/dist/index.js');
const ort = require(path+'packages/core/node_modules/onnxruntime-node');
const EX = new Set(['status_code','req_count_1s','req_count_5s','req_count_60s','error_rate_4xx_60s','endpoint_diversity_60s','non_json_quote_count']);
(async()=>{
 const s=await ort.InferenceSession.create(path+'training/models/rf.onnx');
 const lines=fs.readFileSync('/tmp/benign_eq1.jsonl','utf8').split('\n').filter(Boolean);
 const agg={};
 for(const l of lines){
  const r=JSON.parse(l);
  const v=extractFeatureVector(r).filter((_,i)=>!EX.has(FEATURE_NAMES[i]));
  const t=new ort.Tensor('float32',Float32Array.from(v),[1,v.length]);
  const p=(await s.run({[s.inputNames[0]]:t}))[s.outputNames[1]].data;
  let m=0;for(let i=1;i<5;i++) if(p[i]>p[m]) m=i; 
  const maxi=[...p].indexOf(Math.max(...p));
  const fp = maxi!==0 && p[maxi]>=0.35;
  const uaBrowser=(r.userAgent||'').length>40;
  const plen=(r.path||'').length>15?'path>15':'path<=15';
  const k=plen+' | '+(uaBrowser?'UA long(>40)':'UA short/none');
  (agg[k]??={n:0,fp:0,sqli:0}); agg[k].n++; if(fp){agg[k].fp++; if(maxi===3) agg[k].sqli++;}
 }
 for(const [k,a] of Object.entries(agg).sort()) console.log(k.padEnd(34),'n='+String(a.n).padEnd(6),'FP='+a.fp,'('+(a.fp/a.n*100).toFixed(1)+'%)','sqli-FP='+a.sqli);
})();
