const path='/Users/diego/Uvg/Proyecto de Graduacion/logSguarDian/';
const { extractFeatureVector, FEATURE_NAMES } = require(path+'packages/extractor/dist/index.js');
const ort = require(path+'packages/core/node_modules/onnxruntime-node');
const EXCLUDED = new Set(['status_code','req_count_1s','req_count_5s','req_count_60s','error_rate_4xx_60s','endpoint_diversity_60s','non_json_quote_count']);
const classes = ['benign','cmdi','path_traversal','sqli','xss'];
const names = FEATURE_NAMES.filter(n=>!EXCLUDED.has(n));
async function run(label, req){
  const session = await ort.InferenceSession.create(path+'training/models/rf.onnx');
  const vec = extractFeatureVector(req);
  const modelVec = vec.filter((_, i) => !EXCLUDED.has(FEATURE_NAMES[i]));
  const tensor = new ort.Tensor('float32', Float32Array.from(modelVec), [1, modelVec.length]);
  const result = await session.run({ [session.inputNames[0]]: tensor });
  const probs = result[session.outputNames[1]].data;
  console.log('\n##', label, JSON.stringify(req.path+'?'+req.query), 'nfeat', modelVec.length);
  console.log(classes.map((c,i)=>c+'='+probs[i].toFixed(3)).join(' '));
  console.log(names.map((n,i)=>[n,modelVec[i]]).filter(([,v])=>v!==0).map(([n,v])=>n+'='+v).join('  '));
}
(async()=>{
  const base={method:'GET',userAgent:'curl/8.7.1',contentType:'',referer:'',cookie:'',extraHeaders:{},body:''};
  await run('juice search', {...base,path:'/rest/products/search',query:'q=apple'});
  await run('juice search empty', {...base,path:'/rest/products/search',query:'q='});
  await run('juice foo/search (passed)', {...base,path:'/rest/foo/search',query:'q=apple'});
  await run('juice languages (passed)', {...base,path:'/rest/languages',query:''});
  await run('own app style', {...base,path:'/posts/search',query:'q=apple'});
  await run('own app style no query', {...base,path:'/posts',query:''});
})().catch(e=>console.error(e));
