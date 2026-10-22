// GitHub-only test observation: never records URL/query/body/header/token data.
import express from 'express';
import fs from 'node:fs';
import crypto from 'node:crypto';
const requests=[],original=express.application.handle;
const hash=x=>typeof x==='string'?crypto.createHash('sha256').update(x).digest('hex').slice(0,12):null;
express.application.handle=function(req,res,next){
 res.once('finish',()=>{
  let path=req.route?.path;if(!path)return;
  if(Array.isArray(path))path=path.find(p=>typeof p==='string'&&new RegExp('^'+p.replace(/:[A-Za-z]+/g,'[^/]+')+'$').test(req.path));
  if(typeof path!=='string')return;
  requests.push({method:req.method,route:path,status:res.statusCode,role:['worker','manager','agent','superadmin'].includes(req.user?.role)?req.user.role:'anonymous',actor:hash(req.user?.id),workspace:hash(req.user?.workspace_id),sessionBound:typeof req.sessionId==='string'});
 });
 return original.call(this,req,res,next);
};
process.on('exit',()=>{if(process.env.GITHUB_ACTIONS==='true'){fs.mkdirSync('reports',{recursive:true});fs.writeFileSync('reports/unit-routes-'+process.pid+'.json',JSON.stringify({requests,containsSecrets:false}));}});
