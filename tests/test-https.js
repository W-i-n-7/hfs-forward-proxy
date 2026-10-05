const http=require('http'),https=require('https'),fs=require('fs');const p=require(require('path').resolve(process.env.PLUGIN || './plugin.js'))
const conf={users:[{username:'u',password:'p'}],allowOtherPorts:true,portListIsWhitelist:false,allowLanIpAccess:true}
const srv=http.createServer((q,s)=>s.end('HFS'))
;(async()=>{await p.init({getConfig:()=>conf,log:console.log,onServer:cb=>cb(srv)});srv.listen(8101)
https.createServer({key:fs.readFileSync(__dirname+'/k.pem'),cert:fs.readFileSync(__dirname+'/c.pem')},(q,s)=>s.end('TLS '+q.headers.host+q.url)).listen(9443,()=>{
 for(const u of ['https://localhost:9443/sni','https://127.0.0.1:9443/ip'])
 http.get({host:'127.0.0.1',port:8101,path:u,headers:{'proxy-authorization':'Basic '+Buffer.from('u:p').toString('base64')}},r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>console.log(u,r.statusCode,d.trim()))})
 setTimeout(()=>process.exit(),2000)})})()
