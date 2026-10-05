const http=require('http'),net=require('net');const p=require(require('path').resolve(process.env.PLUGIN || './plugin.js'))
let conf={users:[{username:'u',password:'p:x'}],allowOtherPorts:true,portListIsWhitelist:false,allowLanIpAccess:true,fail2banMaxAttempts:3}
const srv=http.createServer((q,s)=>s.end('HFS'+q.url))
const R=[];const ok=(n,c,e='')=>R.push(`${c?'PASS':'FAIL'} ${n} ${c?'':e}`)
const auth='Basic '+Buffer.from('u:p:x').toString('base64'),bad='Basic '+Buffer.from('u:wrong').toString('base64')
const raw=(data,ms=600,port=8100)=>new Promise(r=>{const c=net.connect(port,'127.0.0.1',()=>c.write(data));let o='';c.on('data',d=>o+=d);c.on('error',()=>{});c.on('close',()=>r(o));setTimeout(()=>{c.destroy();r(o)},ms)})
const get=(path,headers={})=>new Promise(r=>{http.get({host:'127.0.0.1',port:8100,path,headers,agent:false},res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>r({s:res.statusCode,d,h:res.headers}));res.on('error',e=>r({err:e.message}))}).on('error',e=>r({err:e.message}))})
const A={'proxy-authorization':auth}
;(async()=>{
 const plug=await p.init({getConfig:()=>conf,log:()=>{},onServer:cb=>cb(srv)})
 await new Promise(r=>srv.listen(8100,r))
 const tgt=http.createServer((q,s)=>{ if(q.url==='/die'){s.writeHead(200,{'content-length':100});s.write('partial');setTimeout(()=>s.socket.destroy(),100);return}
   if(q.url==='/slow'){return}
   s.setHeader('x-pa',q.headers['proxy-authorization']||'none');s.setHeader('x-ka',q.headers['keep-alive']||'none');s.end('T'+q.url)})
 tgt.on('upgrade',(q,sock)=>sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nWSOK'+q.url))
 await new Promise(r=>tgt.listen(9200,'::',r))
 let x,o
 x=await get('/normal');ok('normal HFS request untouched',x.d==='HFS/normal',JSON.stringify(x))
 x=await get('http://127.0.0.1:9200/a',{...A,'keep-alive':'timeout=5',connection:'keep-alive'});ok('HTTP proxy other port',x.d==='T/a',JSON.stringify(x))
 ok('proxy-authorization + hop-by-hop not forwarded',x.h['x-pa']==='none'&&x.h['x-ka']==='none',JSON.stringify(x.h))
 o=await raw(`GET http://127.0.0.1:9200/a/../b%7e?q=1 HTTP/1.1\r\nHost: x\r\nProxy-Authorization: ${auth}\r\nConnection: close\r\n\r\n`);ok('raw path forwarded unchanged',o.includes('T/a/../b%7e?q=1'),o.slice(-40))
 x=await get('http://[::1]:9200/v6',A);ok('IPv6 literal URL',x.d==='T/v6',JSON.stringify(x))
 x=await get('http://127.0.0.1:9200/die',A);ok('upstream dies mid-body -> client error',!!x.err||x.d.length<100,JSON.stringify(x))
 o=await raw(`CONNECT 127.0.0.1:9200 HTTP/1.1\r\nProxy-Authorization: ${auth}\r\n\r\nGET /c HTTP/1.1\r\nHost: x\r\n\r\n`);ok('CONNECT other port (+head bytes)',o.startsWith('HTTP/1.1 200')&&o.includes('T/c'),o)
 o=await raw(`CONNECT [::1]:9200 HTTP/1.1\r\nProxy-Authorization: ${auth}\r\n\r\n`);ok('CONNECT IPv6',o.startsWith('HTTP/1.1 200'))
 o=await raw(`CONNECT 127.0.0.1:99999 HTTP/1.1\r\nProxy-Authorization: ${auth}\r\n\r\n`);ok('CONNECT invalid port -> 400',o.startsWith('HTTP/1.1 400'))
 o=await raw(`GET ws://127.0.0.1:9200/w HTTP/1.1\r\nHost: 127.0.0.1:9200\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nProxy-Authorization: ${auth}\r\n\r\n`);ok('ws:// upgrade',o.includes('101')&&o.includes('WSOK/w'),o)
 o=await raw(`GET http://127.0.0.1:9200/w2 HTTP/1.1\r\nHost: 127.0.0.1:9200\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nProxy-Authorization: ${auth}\r\n\r\n`);ok('http:// absolute-form upgrade',o.includes('WSOK/w2'),o)
 o=await raw(`GET wss://127.0.0.1:9200/w HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nProxy-Authorization: ${auth}\r\n\r\n`);ok('wss:// upgrade -> 400',o.startsWith('HTTP/1.1 400'),o)
 o=await raw(`GET /h2 HTTP/1.1\r\nHost: a\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: AAA\r\n\r\n`);ok('non-proxy upgrade served normally by HFS',o.includes('200')&&o.includes('HFS/h2'),JSON.stringify(o))
 o=await raw(`CONNECT 127.0.0.1:1 HTTP/1.1\r\nProxy-Authorization: ${auth}\r\n\r\n`);ok('CONNECT refused -> 502',o.startsWith('HTTP/1.1 502'))
 o=await raw(`CONNECT nonexistent.invalid:443 HTTP/1.1\r\nProxy-Authorization: ${auth}\r\n\r\n`,10000);ok('DNS failure -> 502',o.startsWith('HTTP/1.1 502'),o.slice(0,20))
 conf.allowLanIpAccess=false
 for(const h of ['[::ffff:7f00:1]','[0:0:0:0:0:0:0:1]','[::127.0.0.1]','[64:ff9b::7f00:1]','[2002:7f00:1::1]','[64:ff9b::a00:1]']){o=await raw(`CONNECT ${h}:9200 HTTP/1.1\r\nProxy-Authorization: ${auth}\r\n\r\n`);ok('blocked '+h,o.startsWith('HTTP/1.1 403'),o.slice(0,30))}
 x=await get('http://localhost:9200/',A);ok('localhost blocked',x.s===403)
 conf.allowLanIpAccess=true;conf.lanIpListIsWhitelist=true;conf.lanIpList=[{ip:'0:0::1'}]
 x=await get('http://[::1]:9200/wl',A);ok('LAN whitelist non-canonical entry',x.d==='T/wl',JSON.stringify(x))
 x=await get('http://127.0.0.1:9200/wl',A);ok('LAN whitelist excludes others',x.s===403)
 conf.lanIpListIsWhitelist=false;conf.lanIpList=[{ip:'127.0.0.1'}]
 x=await get('http://127.0.0.1:9200/',A);ok('LAN blacklist',x.s===403)
 conf.lanIpList=[]
 conf.portListIsWhitelist=true;conf.additionalAllowedPorts=[]
 x=await get('http://127.0.0.1:9200/',A);ok('port whitelist empty blocks',x.s===403)
 conf.additionalAllowedPorts=[{port:9200}];x=await get('http://127.0.0.1:9200/',A);ok('port whitelist allows',x.s===200)
 conf.portListIsWhitelist=false;x=await get('http://127.0.0.1:9200/',A);ok('port blacklist blocks',x.s===403)
 conf.allowOtherPorts=false;conf.additionalAllowedPorts=[];x=await get('http://127.0.0.1:9200/',A);ok('allowOtherPorts off blocks',x.s===403)
 conf.allowOtherPorts=true
 const sts=[];for(let i=0;i<6;i++)sts.push((await get('http://127.0.0.1:9200/')).s)
 ok('missing credentials never ban',sts.every(s=>s===407),JSON.stringify(sts))
 x=await get('http://127.0.0.1:9200/',A);ok('still allowed after credential-less 407s',x.s===200)
 const st2=[];for(let i=0;i<4;i++)st2.push((await get('http://127.0.0.1:9200/',{'proxy-authorization':bad})).s)
 ok('wrong credentials ban after 3',JSON.stringify(st2)==='[407,407,403,403]',JSON.stringify(st2))
 x=await get('http://127.0.0.1:9200/',A);ok('banned even with right password',x.s===403)
 x=await get('/normal');ok('banned client still reaches HFS',x.d==='HFS/normal')
 plug.unload()
 x=await get('http://127.0.0.1:9200/',A);ok('after unload HFS handles everything',x.d.startsWith('HFS'),JSON.stringify(x))
 o=await raw(`GET /h2 HTTP/1.1\r\nHost: a\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n`);ok('after unload upgrade behaves natively',o.includes('HFS/h2'),o)
 console.log(R.join('\n'));console.log(R.filter(x=>x.startsWith('FAIL')).length+' failures / '+R.length);process.exit()
})()
