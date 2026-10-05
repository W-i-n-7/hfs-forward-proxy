// DNS behaviour: c-ares first, OS lookup fallback for local names, cache, concurrency cap, timeout.
// Node's DNS functions are replaced with mocks, so no network is needed.
const http=require('http'),dnsP=require('dns').promises
const calls={resolve4:0,resolve6:0,lookup:0};let lookupActive=0,lookupMax=0
const cares={'pub.example':'127.0.0.1','short-ttl.example':'127.0.0.1','priv.example':'10.1.2.3'}
const err=c=>Object.assign(new Error(c),{code:c})
dnsP.Resolver.prototype.resolve4=async function(h){calls.resolve4++;if(cares[h]){const rec={address:cares[h],ttl:h==='short-ttl.example'?1:300};return [rec]}throw err('ENOTFOUND')}
dnsP.Resolver.prototype.resolve6=async function(h){calls.resolve6++;throw err(cares[h]?'ENODATA':'ENOTFOUND')}
dnsP.lookup=async function(h){calls.lookup++;lookupActive++;lookupMax=Math.max(lookupMax,lookupActive)
 try{ if(h==='hang.local')await new Promise(()=>{}); if(h.startsWith('slow'))await new Promise(r=>setTimeout(r,400))
  if(['hostsonly.example','myrouter','nas.local'].includes(h)||h.startsWith('slow')){const rec={address:'127.0.0.1',family:4};return [rec]} throw err('ENOTFOUND') } finally{lookupActive--}}
const p=require(require('path').resolve(process.env.PLUGIN || './plugin.js'))
const conf={users:[{username:'u',password:'p'}],allowOtherPorts:true,portListIsWhitelist:false,allowLanIpAccess:true}
const srv=http.createServer((q,s)=>s.end('HFS'));const R=[];const ok=(n,c,e='')=>R.push(`${c?'PASS':'FAIL'} ${n} ${c?'':e}`)
const A={'proxy-authorization':'Basic '+Buffer.from('u:p').toString('base64')}
const get=host=>new Promise(r=>{const t0=Date.now();http.get({host:'127.0.0.1',port:8105,path:`http://${host}:9501/`,headers:A,agent:false},res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>r({s:res.statusCode,d:d.trim(),ms:Date.now()-t0}))}).on('error',e=>r({err:e.message}))})
const snap=()=>({...calls})
;(async()=>{await p.init({getConfig:()=>conf,log:()=>{},onServer:cb=>cb(srv)});await new Promise(r=>srv.listen(8105,r))
 await new Promise(r=>http.createServer((q,s)=>s.end('T')).listen(9501,'127.0.0.1',r))
 let b=snap(),x=await get('pub.example');ok('public name via c-ares, no OS lookup',x.s===200&&calls.resolve4-b.resolve4===1&&calls.lookup===b.lookup,JSON.stringify({x,calls}))
 b=snap();x=await get('PUB.example');ok('cached (case-insensitive), no new queries',x.s===200&&calls.resolve4===b.resolve4&&calls.lookup===b.lookup,JSON.stringify(calls))
 b=snap();await get('short-ttl.example');await get('short-ttl.example');ok('TTL of 1s is raised to the 5s minimum',calls.resolve4-b.resolve4===1,JSON.stringify(calls))
 b=snap();x=await get('hostsonly.example');ok('c-ares miss falls back to OS lookup (hosts file)',x.s===200&&calls.resolve4-b.resolve4===1&&calls.lookup-b.lookup===1,JSON.stringify({x,calls}))
 b=snap();x=await get('myrouter');ok('single-label name goes straight to OS lookup',x.s===200&&calls.resolve4===b.resolve4&&calls.lookup-b.lookup===1,JSON.stringify(calls))
 b=snap();x=await get('nas.local');ok('.local name goes straight to OS lookup',x.s===200&&calls.resolve4===b.resolve4&&calls.lookup-b.lookup===1)
 b=snap();x=await get('127.0.0.1');ok('IP literal needs no DNS',x.s===200&&calls.resolve4===b.resolve4&&calls.lookup===b.lookup)
 b=snap();x=await get('nothing.example');ok('unknown name -> 502',x.s===502,JSON.stringify(x))
 conf.allowLanIpAccess=false;x=await get('priv.example');ok('private result from c-ares still blocked',x.s===403,JSON.stringify(x));conf.allowLanIpAccess=true
 lookupMax=0;const rs=await Promise.all([1,2,3,4,5,6].map(i=>get(`slow${i}.local`)))
 ok('at most 2 OS lookups at once',lookupMax===2,'max='+lookupMax);ok('queued lookups all complete',rs.every(r=>r.s===200),JSON.stringify(rs.map(r=>r.s)))
 x=await get('hang.local');ok('hung lookup times out with 502 after ~8s',x.s===502&&/timed out/.test(x.d)&&x.ms>7500&&x.ms<9500,JSON.stringify(x))
 console.log(R.join('\n'));console.log(R.filter(r=>r.startsWith('FAIL')).length+' failures / '+R.length);process.exit()})()
