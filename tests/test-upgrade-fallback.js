const http=require('http'),net=require('net');const p=require(require('path').resolve(process.env.PLUGIN || './plugin.js'))
const srv=http.createServer((q,s)=>{let ended=false;q.on('end',()=>{ended=true});q.resume();setTimeout(()=>s.end('end='+ended+' '+q.url),200)})
;(async()=>{await p.init({getConfig:()=>({users:[]}),log:()=>{},onServer:cb=>cb(srv)});srv.listen(8102,()=>{
for(const body of ['','POST'])
{const c=net.connect(8102,'127.0.0.1',()=>c.write(body?`POST /p HTTP/1.1\r\nHost: a\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nContent-Length: 5\r\n\r\nhello`:`GET /g HTTP/1.1\r\nHost: a\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n`));let o='';c.on('data',d=>o+=d);c.on('close',()=>console.log(JSON.stringify(o.split('\r\n\r\n')[1])))}
setTimeout(()=>process.exit(),1500)})})()
