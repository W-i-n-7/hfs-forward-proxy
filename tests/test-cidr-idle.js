const http=require('http'),net=require('net');const p=require(require('path').resolve(process.env.PLUGIN || './plugin.js'))
const conf={users:[{username:'u',password:'p'}],allowOtherPorts:true,portListIsWhitelist:false,allowLanIpAccess:true,lanIpListIsWhitelist:true}
const srv=http.createServer((q,s)=>s.end('HFS'));const R=[];const ok=(n,c,e='')=>R.push(`${c?'PASS':'FAIL'} ${n} ${c?'':e}`)
const A={'proxy-authorization':'Basic '+Buffer.from('u:p').toString('base64')}
const get=(path)=>new Promise(r=>{const t0=Date.now();http.get({host:'127.0.0.1',port:8104,path,headers:A,agent:false},res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>r({s:res.statusCode,d,ms:Date.now()-t0}));res.on('error',e=>r({err:e.message,ms:Date.now()-t0}))}).on('error',e=>r({err:e.message,ms:Date.now()-t0}))})
const tunnel=(ms)=>new Promise(r=>{const t0=Date.now();const c=net.connect(8104,'127.0.0.1',()=>c.write(`CONNECT 127.0.0.1:9401 HTTP/1.1\r\nProxy-Authorization: ${A['proxy-authorization']}\r\n\r\n`));let o='';c.on('data',d=>o+=d);c.on('close',()=>r({o,closedAfter:Date.now()-t0}));setTimeout(()=>{c.destroy();r({o,closedAfter:null})},ms)})
;(async()=>{const logs=[];await p.init({getConfig:()=>conf,log:(...a)=>logs.push(a.join(' ')),onServer:cb=>cb(srv)});await new Promise(r=>srv.listen(8104,r))
 await new Promise(r=>http.createServer((q,s)=>{if(q.url==='/stall'){s.writeHead(200);s.write('x');return}s.end('T')}).listen(9401,'::',r))
 const cases=[[['127.0.0.0/8'],'127.0.0.1',200],[['127.0.0.2/32'],'127.0.0.1',403],[['10.0.0.0/8'],'127.0.0.1',403],[['::1/128'],'[::1]',200],[['::/0'],'[::1]',200],[['0.0.0.0/0'],'127.0.0.1',200],[['::ffff:127.0.0.0/104'],'127.0.0.1',200],[['127.0.0.1'],'127.0.0.1',200],[['  127.0.0.0 / 24 '],'127.0.0.1',200]]
 for(const [list,host,exp] of cases){conf.lanIpList=list.map(ip=>({ip}));const x=await get(`http://${host}:9401/`);ok(`whitelist ${list} -> ${host} = ${exp}`,x.s===exp,JSON.stringify(x))}
 conf.lanIpList=[{ip:'127.0.0.0/33'},{ip:'nonsense'},{ip:'1.2.3.4/8/9'},{ip:'127.0.0.0/abc'}];let x=await get('http://127.0.0.1:9401/');ok('invalid entries ignored (whitelist -> blocked)',x.s===403);ok('invalid entries logged',logs.filter(l=>l.includes('ignoring invalid')).length===4,JSON.stringify(logs))
 conf.lanIpListIsWhitelist=false;conf.lanIpList=[{ip:'127.0.0.0/8'}];x=await get('http://127.0.0.1:9401/');ok('blacklist CIDR blocks',x.s===403)
 x=await get('http://[::1]:9401/');ok('blacklist v4 CIDR does not block ::1',x.s===200)
 conf.lanIpList=[]
 conf.idleTimeoutSeconds=1;x=await get('http://127.0.0.1:9401/stall');ok('stalled HTTP download closed after idle timeout',!!x.err&&x.ms>=900&&x.ms<2500,JSON.stringify(x))
 let t=await tunnel(4000);ok('idle tunnel closed after timeout',t.closedAfter&&t.closedAfter>=900&&t.closedAfter<2500,JSON.stringify(t))
 conf.idleTimeoutSeconds=0;t=await tunnel(2500);ok('idle 0 keeps tunnel open',t.closedAfter===null&&t.o.includes('200'),JSON.stringify(t))
 delete conf.idleTimeoutSeconds;x=await get('http://127.0.0.1:9401/');ok('default config works',x.s===200)
 console.log(R.join('\n'));console.log(R.filter(r=>r.startsWith('FAIL')).length+' failures / '+R.length);process.exit()})()
