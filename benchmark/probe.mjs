import {readFileSync,writeFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const pkg=readFileSync(path.join(root,'benchmark/installer/package-path.txt'),'utf8').trim();
const {Client}=await import(path.join(pkg,'../@modelcontextprotocol/client/dist/index.mjs'));
const {StdioClientTransport}=await import(path.join(pkg,'../@modelcontextprotocol/client/dist/stdio.mjs'));
const [arm,directory]=process.argv.slice(2);
const client=new Client({name:'fixture-contract-probe',version:'1'});
const transport=new StdioClientTransport({command:path.join(root,'.venv/bin/python'),args:[path.join(root,'benchmark/relay.py'),path.join(directory,'engine.sock')],stderr:'pipe'});
await client.connect(transport);
const tools=(await client.listTools()).tools;
const calls=arm==='ours'?[['search',{kind:'strings',pattern:'eaos fixture anchor'}],['inspect',{addresses:['100000460'],mode:'decompile'}],['read_evidence',{id:'../private/doom/answer-key.json'}]]:
 arm==='community'?[['list_strings',{filter:'eaos fixture anchor'}],['decompile_function_by_address',{address:'100000460'}]]:
 [['search_strings',{pattern:'eaos fixture anchor'}],['procedure_pseudo_code',{procedure:'100000460'}],['read_workflow_document',{path:'SKILL.md'}],['open_binary',{path:path.join(root,'private/doom/answer-key.json'),provider_id:'ghidra'}]];
const results=[];
try{
 for(const [name,args] of calls){
  try{results.push({name,args,result:await client.callTool({name,arguments:args},{timeout:120000})});}
  catch(error){results.push({name,args,error:String(error)});}
 }
 writeFileSync(path.join(directory,'probe.json'),JSON.stringify({arm,tools:tools.length,results},null,2));
 console.log(JSON.stringify({arm,tools:tools.length,calls:results.map(x=>({name:x.name,isError:x.result?.isError,error:x.error,text:JSON.stringify(x.result??{}).slice(0,130)}))}));
}finally{await client.close();}
