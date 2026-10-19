// Run-local adapter: stock schemas/results; only target and installed docs are accessible.
import {readFileSync,writeFileSync,appendFileSync,mkdirSync} from 'node:fs';
import {createServer} from 'node:net';
import {createInterface} from 'node:readline';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {validateArguments,validatePaths,workflowPath} from './scope.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const [arm,target,runDir]=process.argv.slice(2);
const pkg=readFileSync(path.join(root,'benchmark/installer/package-path.txt'),'utf8').trim();
const {Client}=await import(path.join(pkg,'../@modelcontextprotocol/client/dist/index.mjs'));
const {StdioClientTransport}=await import(path.join(pkg,'../@modelcontextprotocol/client/dist/stdio.mjs'));
const jdk=path.join(root,'.tools/jdk-21.0.12.1+1/Contents/Home');
const ghidra=path.join(root,'.tools/ghidra_12.1.4_PUBLIC');
const skill=path.join(root,'benchmark/installer/home/.agents/skills/reverse-engineer-anything');
const began=performance.now();
const log=o=>appendFileSync(path.join(runDir,'tools.jsonl'),JSON.stringify({time:new Date().toISOString(),...o})+'\n');
const env={...process.env,JAVA_HOME:jdk,GHIDRA_INSTALL_DIR:ghidra,PATH:`${jdk}/bin:${process.env.PATH}`};
let command,args;
if(arm==='ours'){
 command=path.join(root,'.venv/bin/eaos');args=['mcp',target];
}else if(arm==='rea'){
 command=process.execPath;args=[path.join(pkg,'scripts/rea.mjs'),'mcp'];
 env.REA_GHIDRA_STARTUP_TIMEOUT_MS='3600000';
 env.HOME=path.join(root,'benchmark/installer/home');
 env.XDG_CACHE_HOME=path.join(runDir,'runtime-cache');
}else if(arm==='community'){
 command=path.join(root,'benchmark/vendor/GhidraMCP/.venv/bin/python');
 env.PYTHONPATH=path.join(root,'benchmark/vendor/GhidraMCP/src');
 env.JAVA_TOOL_OPTIONS=`-Duser.home=${path.join(runDir,'java-state')} -Xmx4G`;
 args=['-m','ghidra_mcp','--headless','--binary',target,'--project',path.join(runDir,'project'),
 '--project-name','program','--no-analyze','--discard','--ghidra-install-dir',ghidra,
 '--extension-jar',path.join(root,'benchmark/vendor/GhidraMCP.jar'),'--ready-timeout','240','--timeout','180'];
}else throw new Error('Unknown arm');
mkdirSync(runDir,{recursive:true});
mkdirSync(path.join(runDir,'java-state'),{recursive:true});
const client=new Client({name:'eaos-doom-comparison',version:'1'});
const transport=new StdioClientTransport({command,args,env,stderr:'pipe'});
transport.stderr?.on('data',d=>appendFileSync(path.join(runDir,'engine.log'),d));
await client.connect(transport);
const original=await client.listTools();
const catalog=[...original.tools];
if(arm!=='ours')catalog.push({name:'calculate',description:'Pure arithmetic/bytes Python expression, without file, network or program execution. Shared calculator in all conditions.',inputSchema:{type:'object',properties:{expression:{type:'string'}},required:['expression'],additionalProperties:false}});
if(arm==='rea')catalog.push({name:'read_workflow_document',description:'Read installed REA skill documentation, by SKILL.md or references/<name>.md. Only installed Markdown; no source code, answer keys or arbitrary files.',inputSchema:{type:'object',properties:{path:{type:'string'}},required:['path'],additionalProperties:false}});
let opened=await client.callTool(arm==='ours'?{name:'open_program',arguments:{}}:arm==='rea'?{name:'open_binary',arguments:{path:target,provider_id:'ghidra'}}:{name:'get_program_info',arguments:{}},{timeout:3600000});
// Asynchronous EAOS initialization must finish outside the agent timer too.
const preparationDeadline=performance.now()+3600000;
while(arm==='ours'&&!opened.isError){
 const status=JSON.parse(opened.content[0].text).data?.analysis;
 if(!status)break;
 if(status.state!=='running'||performance.now()>preparationDeadline)throw new Error('EAOS preparation failed or exceeded the one-hour audit ceiling');
 await new Promise(resolve=>setTimeout(resolve,2000));
 opened=await client.callTool({name:'open_program',arguments:{}},{timeout:30000});
}
writeFileSync(path.join(runDir,'open-result.json'),JSON.stringify(opened,null,2));
if(opened.isError)throw new Error('Backend preparation failed; see open-result.json');
if(arm==='rea'){
 // Stock open_binary is lazy: force the same analyzed readiness as the other arms.
 const warm=await client.callTool({name:'list_procedures',arguments:{}},{timeout:3600000});
 writeFileSync(path.join(runDir,'warmup-result.json'),JSON.stringify(warm,null,2));
 if(warm.isError)throw new Error('REA analysis warmup failed; see warmup-result.json');
}
writeFileSync(path.join(runDir,'catalog.json'),JSON.stringify(catalog,null,2));
// Round 2: identical first-function decompiler warmup outside agent time.
if(process.env.EAOS_STUDY_PROFILE==='round2'){
 const address=process.env.EAOS_WARMUP_ADDRESS;
 if(!/^[0-9a-f]+$/.test(address??''))throw new Error('Missing generic warmup address');
 const request=arm==='ours'?{name:'inspect',arguments:{addresses:[address]}}:
  arm==='rea'?{name:'procedure_pseudo_code',arguments:{procedure:address}}:
  {name:'decompile_function_by_address',arguments:{address}};
 const warm=await client.callTool(request,{timeout:240000});
 writeFileSync(path.join(runDir,'decompiler-warmup.json'),JSON.stringify({request,result:warm},null,2));
 if(warm.isError)throw new Error('Decompiler prewarming failed');
}
// Read-only static-native scope. Full stock REA catalog is still exposed (and charged).
const native=new Set(['binary_overview','list_procedures','search_procedures','list_strings','search_strings','procedure_pseudo_code','procedure_assembly','procedure_callers','procedure_callees','procedure_references','xrefs','inspect_native_data_type','resolve_containing_procedure','inspect_native_instruction','resolve_native_call_targets','read_bytes','analyze_function','batch_decompile','trace_feature','trace_call_path','trace_native_values','inspect_native_api','inspect_analysis_view','get_evidence_bundle','inspect_native_load_image','inspect_native_dispatch_metadata','address_name','comment','current_address','current_procedure','current_document','goto_address','inline_comment','list_bookmarks','list_documents','list_names','list_segments','next_address','prev_address','procedure_address','procedure_info','read_function_instructions','search_bytes','address_to_file_offset','get_objc_classes','get_objc_protocols','get_call_graph','analyze_swift_types','find_xrefs_to_name','inspect_macho','inspect_signature','list_architectures','demangle_swift','open_binary','binary_session','export_evidence_bundle','get_navigation_context','inspect_address_context','list_unknowns']);
if(process.env.EAOS_STUDY_PROFILE==='round2')native.add('close_binary');
async function call(name,arguments_){
 validateArguments(catalog,name,arguments_);
 if(name==='read_workflow_document'){
  if(arm!=='rea')throw new Error('No installed workflow for this condition');
  const file=workflowPath(skill,arguments_.path);
  const bytes=readFileSync(file);
  return {content:[{type:'text',text:JSON.stringify({path:file,sha256:createHash('sha256').update(bytes).digest('hex'),text:bytes.toString('utf8')})}]};
 }
 if(name==='calculate'&&arm!=='ours'){
  const result=spawnSync(path.join(root,'.venv/bin/python'),['-I',path.join(root,'src/eaos/calculator.py')],{input:JSON.stringify(arguments_),encoding:'utf8',timeout:4000,maxBuffer:100000});
  return {content:[{type:'text',text:result.status===0?result.stdout:result.stderr}],...(result.status===0?{}:{isError:true})};
 }
 if(arm==='rea'){
  if(!native.has(name))throw new Error('This is static native analysis of one selected target. Runtime, other targets, arbitrary files and external tools are outside scope.');
 }
 validatePaths(name,arguments_,{target,runDir,serverPath:command===process.execPath?args[0]:command});
 return await client.callTool({name,arguments:arguments_},{timeout:180000});
}
let server;
const socketPath=path.join(runDir,'engine.sock');
let serial=Promise.resolve();
server=createServer(socket=>{
 const lines=createInterface({input:socket});
 lines.on('line',line=>{
  serial=serial.then(async()=>{
   let request;try{request=JSON.parse(line);}catch{return;}
   if(request.id===undefined)return;
   let response;
   try{
    let result;
    if(request.method==='initialize')result={protocolVersion:request.params.protocolVersion,capabilities:{tools:{}},serverInfo:{name:arm,version:'1'}};
    else if(request.method==='ping')result={};
    else if(request.method==='tools/list')result={tools:catalog};
    else if(request.method==='tools/call'){
     const start=performance.now();result=await call(request.params.name,request.params.arguments??{});
     log({event:'call',name:request.params.name,arguments:request.params.arguments,elapsed_ms:performance.now()-start,isError:result.isError===true,result_bytes:Buffer.byteLength(JSON.stringify(result)),result});
    }else throw new Error('Unsupported method');
    response={jsonrpc:'2.0',id:request.id,result};
   }catch(error){log({event:'error',error:String(error),request});response={jsonrpc:'2.0',id:request.id,error:{code:-32603,message:String(error)}};}
   socket.write(JSON.stringify(response)+'\n');
  }).catch(error=>log({event:'fatal',error:String(error)}));
 });
});
await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(socketPath,resolve);});
const ready={ready:true,arm,target,setup_seconds:(performance.now()-began)/1000,stock_tool_count:original.tools.length,exposed_tool_count:catalog.length};
writeFileSync(path.join(runDir,'ready.json'),JSON.stringify(ready,null,2));log({event:'ready',...ready});
let closing=false;
async function cleanup(){if(closing)return;closing=true;server.close();try{await client.close();}catch{}process.exit(0);}
process.on('SIGTERM',cleanup);process.on('SIGINT',cleanup);
