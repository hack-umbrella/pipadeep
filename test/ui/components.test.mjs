import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../../dev/pentest-ui-components.js', import.meta.url), 'utf8');
const deferred = () => { let resolve, reject; const promise = new Promise((a,b) => {resolve=a;reject=b;}); return { promise, resolve, reject }; };

function setup(name, props) {
  const instances = new Map(); let active; let cursor; let dirty = true; let tree; let effects = []; let currentProps = props;
  const calls = []; const copied = []; const downloads = []; let copyFailure = false;
  const jsx = (type, props, key) => ({ type, props: props || {}, key });
  const react = {
    useState(initial) { const i=cursor++; const a=active; if (!(i in a.hooks)) a.hooks[i] = typeof initial === 'function' ? initial() : initial; return [a.hooks[i], value => {a.hooks[i] = typeof value === 'function' ? value(a.hooks[i]) : value;dirty=true;}]; },
    useRef(initial) { const i=cursor++; return active.hooks[i] ||= {current:initial}; },
    useEffect(fn,deps) { const i=cursor++; const a=active; const old=a.hooks[i]; if (!old || !deps || deps.some((d,j)=>!Object.is(d,old.deps?.[j]))) { effects.push(()=>{old?.cleanup?.();a.hooks[i]={deps,cleanup:fn()};}); } }
  };
  const context = vm.createContext({ react, react_jsx_runtime:{jsx,jsxs:jsx}, fetch:(url,options)=>{ const d=deferred(); calls.push({url,options,...d});return d.promise; }, navigator:{clipboard:{writeText:async text=>{if(copyFailure) throw Error('denied'); copied.push(text);}}}, Blob, URL:{createObjectURL:blob=>{downloads.push(blob);return 'blob:mock';},revokeObjectURL(){}}, document:{createElement:()=>({click(){}})}, filenameOf:()=> 'report.md', Date, setTimeout:fn=>{fn();return 0;}, console });
  vm.runInContext(source + '\nthis.components={ReportView,RetestView,FindingsView,AssetsView,PtCopy,PtCode,PtContent,PtHttpSide,PtPackets,PtInlineCopy,ptPublicReport};',context);
  const root=context.components[name];
  function walk(node,path,visited) {
    if (node == null || typeof node==='boolean') return null;
    if(Array.isArray(node)) return node.map((n,i)=>walk(n,path+'/'+(n?.key ?? i),visited));
    if(typeof node!=='object') return String(node);
    if(typeof node.type==='function') {
      const id=path+':'+node.type.name;visited.add(id);
      const a=instances.get(id)||{hooks:[]};instances.set(id,a);active=a;cursor=0;
      return walk(node.type(node.props),id,visited);
    }
    if (['input','img','br','hr','meta','link','area','base','col','embed','param','source','track','wbr'].includes(node.type) && Object.hasOwn(node.props,'children')) throw Error('Void element received children: '+node.type);
    return {type:node.type,props:node.props,children:walk(node.props.children,path+'/children',visited)};
  }
  function render(nextProps=currentProps) {
    currentProps=nextProps;dirty=true;let loops=0;
    while(dirty) { if(++loops>30) throw Error('render loop');dirty=false;effects=[];const visited=new Set();tree=walk(jsx(root,currentProps),'root',visited); for(const [id,a] of instances) if(!visited.has(id)){a.hooks.forEach(h=>h?.cleanup?.());instances.delete(id);} for(const effect of effects)effect(); }
    return tree;
  }
  const all = (predicate,node=tree) => Array.isArray(node) ? node.flatMap(n=>all(predicate,n)) : !node || typeof node!=='object' ? [] : [...(predicate(node)?[node]:[]),...all(predicate,node.children)];
  const text = (node=tree) => Array.isArray(node) ? node.map(n=>text(n)).join('') : node == null ? '' : typeof node==='object' ? text(node.children) : String(node);
  const byTest = id => all(n=>n.props['data-testid']===id);
  const button = label => all(n=>n.type==='button'&&(n.props['aria-label']===label||text(n)===label))[0];
  const reply = async (index,data,ok=true) => {calls[index].resolve({ok,status:ok?200:500,json:async()=>data,text:async()=>data});await tick();render();};
  const click = async node => {assert.ok(node,'click target exists');await node.props.onClick();await tick();render();};
  render();
  return {render,all,text,byTest,button,calls,copied,downloads,reply,click,setCopyFailure:v=>{copyFailure=v;},get tree(){return tree;}};
}
async function tick(){for(let i=0;i<12;i++)await Promise.resolve();}

const rowA={key:'a',title:'Issue A',severity:'high',steps:['curl --silent https://demo.example/a'],probe:{verdict:'fixed',detail:'HISTORY SECRET',packets:[{responseBody:'OLD PACKET'}]},evidence:[{path:'/private/history.http'}]};
const rowB={key:'b',title:'Issue B',severity:'medium',description:'普通文字'};
const list={target:'demo.example',baselineName:'baseline 1',diff:{open:[rowA,rowB],fixed:[]},probe:{open:9}};
const packet={method:'POST',url:'https://demo.example/verify',status:200,requestHeaders:{Host:'demo.example','X-Repeat':['a','b']},requestBody:'  {"x":1}\n\n',responseHeaders:{'Content-Type':'application/json'},responseBody:'x'.repeat(9000)+'\n  END  \n',durationMs:123};
const response={key:'a',verdict:'open',detail:'本轮确认',packets:[packet],ranAt:'2025-01-01'};

async function start(){const app=setup('RetestView',{sessionId:'session/A',t:x=>x});await app.reply(0,list);return app;}

test('initial list is read-only, zero runs, no history or packets; selection does not execute',async()=>{
 const app=await start();assert.match(app.calls[0].url,/probe=0/);assert.doesNotMatch(app.calls[0].url,/probe=1/);assert.equal(app.calls.length,1);assert.match(app.text(),/已复测 0 \/ 2/);assert.doesNotMatch(app.text(),/HISTORY SECRET|OLD PACKET|private\/history|全量|全部复测/);assert.equal(app.byTest('pentest-current-packets').length,0);await app.click(app.byTest('pentest-retest-select')[1]);assert.equal(app.calls.length,1);assert.match(app.text(),/Issue B/);
});

test('only explicit row action executes; duplicate clicks blocked; long payload copied exactly',async()=>{
 const app=await start();const run=app.button('一键复测');const p=run.props.onClick();run.props.onClick();app.render();assert.equal(app.calls.length,2);assert.match(app.calls[1].url,/retest\/one\?sessionId=session%2FA&key=a&baseline=baseline%201/);assert.equal(app.byTest('pentest-current-packets').length,0);await app.reply(1,response);await p;app.render();assert.equal(app.byTest('pentest-current-packets').length,1);await app.click(app.button('复制完整响应'));assert.ok(app.copied.at(-1).includes(packet.responseBody));assert.match(app.text(),/已复制/);await app.click(app.button('复制完整请求'));assert.ok(app.copied.at(-1).includes(packet.requestBody));assert.doesNotMatch(app.copied.at(-1),/^1\s/);assert.match(app.text(),/已复测 1 \/ 2/);
 await app.click(app.byTest('pentest-retest-select')[1]);assert.equal(app.byTest('pentest-current-packets').length,0);await app.click(app.byTest('pentest-retest-select')[0]);const again=app.button('一键复测').props.onClick();app.render();assert.equal(app.byTest('pentest-current-packets').length,0);app.calls[2].reject(Error('offline'));await again;app.render();assert.match(app.text(),/执行异常/);assert.doesNotMatch(app.text(),/本轮确认/);
});

test('session switch rejects stale list and pending execution, including A→B→A',async()=>{
 const app=await start();const pending=app.button('一键复测').props.onClick();app.render({sessionId:'B',t:x=>x});assert.equal(app.byTest('pentest-current-packets').length,0);assert.doesNotMatch(app.text(),/Issue A/);await app.reply(2,{...list,diff:{open:[rowB]}});await app.reply(1,response);await pending;app.render();assert.equal(app.byTest('pentest-current-packets').length,0);assert.match(app.text(),/已复测 0 \/ 1/);
});

test('network failure and invalid JSON never imply fixed; no-packet verdict needs confirmation',async()=>{
 const app=await start();
 const p1=app.button('一键复测').props.onClick();app.render();
 await app.reply(1,{key:'a',verdict:'fixed',error:'timeout',packets:[]});await p1;
 assert.match(app.text(),/执行失败/);assert.doesNotMatch(app.all(n=>n.props['data-testid']==='pentest-retest-one-result').map(n=>app.text(n)).join(''),/已修复/);
 const p2=app.button('一键复测').props.onClick();app.render();
 await app.reply(2,{key:'a',verdict:'fixed',packets:[{status:502}]});await p2;
 assert.match(app.text(),/需人工确认/);assert.doesNotMatch(app.all(n=>n.props['data-testid']==='pentest-retest-one-result').map(n=>app.text(n)).join(''),/已修复/);
});

test('copy failure is visible and retry succeeds without copying line numbers',async()=>{
 const app=setup('PtCode',{text:'line1\nline2'});app.setCopyFailure(true);await app.click(app.button('复制完整内容'));assert.match(app.text(),/复制失败/);
 app.setCopyFailure(false);await app.click(app.button('复制完整内容'));assert.equal(app.copied[0],'line1\nline2');assert.match(app.text(),/已复制/);
});

test('HTTP headers/body switches and exchange selection use complete individual raw contents',async()=>{
 const app=setup('PtPackets',{packets:[packet]});assert.equal(app.byTest('pentest-code-viewer').length,2);assert.match(app.text(),/POST/);assert.match(app.text(),/Host: demo\.example/);
});

test('Chinese command prefixes split expected prose, and URLs copy exact inline text',async()=>{
 for (const value of ['1) 执行：curl https://demo.example/a，预期返回403','执行：curl https://demo.example/a，预期：返回403','1. 执行：curl https://demo.example/a，预期返回403']) {
  const app=setup('PtContent',{value});assert.equal(app.byTest('pentest-code-viewer').length,1);await app.click(app.button('复制完整内容'));assert.equal(app.copied[0],'curl https://demo.example/a');assert.match(app.text(),/预期：返回403/);
 }
 const app=setup('PtContent',{value:'目标 https://demo.example/a?x=1&y=2 待验证'});await app.click(app.button('复制地址'));assert.equal(app.copied[0],'https://demo.example/a?x=1&y=2');assert.equal(app.byTest('pentest-code-viewer').length,0);
});

test('ReportView focuses on clean export center rather than rendering verbose prose',async()=>{
 const graph={goal:{target:'demo.example',createdAt:'2026-11-20'},nodes:[{kind:'finding',id:'f-1',severity:'high',title:'SQLi'}],assets:[{id:'a-1',value:'demo.example'}]};
 const app=setup('ReportView',{pentest:graph,sessionId:'A',t:x=>x});
 assert.match(app.calls[0].url,/sessionId=A/);
 await app.reply(0,'# 渗透测试报告\n\n- 目标: demo.example\n\n## 漏洞发现\n\n### [high] SQLi\n');
 assert.match(app.text(),/渗透测试报告交付中心/);
 assert.match(app.text(),/高危\s*1/);
 assert.equal(app.byTest('pentest-report-download').length,1);
 await app.click(app.button('复制报告 Markdown'));
 assert.match(app.copied[0],/SQLi/);
});

test('FindingsView provides compact layout, filtering, and numbered code viewer for commands',async()=>{
 const pentest={assets:[{id:'ast-1',value:'https://demo.example/api/v1'}],nodes:[
   {kind:'finding',id:'finding-1',severity:'high',title:'未授权访问 API',affectedAssetId:'ast-1',description:'接口未校验权限',steps:['执行：curl -i https://demo.example/api/v1，预期返回401']},
   {kind:'finding',id:'finding-2',severity:'low',title:'安全头缺失',affectedAssetId:'ast-1',description:'缺少 CSP'}
 ]};
 const app=setup('FindingsView',{pentest,sessionId:'session-1',t:x=>x});
 assert.equal(app.byTest('pentest-findings').length,1);
 assert.equal(app.byTest('pentest-finding-detail').length,1);
 assert.match(app.text(),/未授权访问 API/);
 // Command in step is rendered as PtCode with line numbers and one-click copy
 assert.equal(app.byTest('pentest-code-viewer').length,1);
 await app.click(app.button('复制完整内容'));
 assert.equal(app.copied[0],'curl -i https://demo.example/api/v1');
});

test('AssetsView renders clean structured inventory table and one-click copy',async()=>{
 const pentest={assets:[
   {id:'ast-1',type:'root-domain',value:'demo.example',meta:'主域'},
   {id:'ast-2',type:'subdomain',value:'api.demo.example',meta:'API网关'}
 ],edges:[{kind:'parent',sourceId:'ast-1',targetId:'ast-2'}]};
 const app=setup('AssetsView',{pentest,t:x=>x});
 assert.equal(app.byTest('pentest-assets').length,1);
 assert.match(app.text(),/资产测绘清单/);
 assert.match(app.text(),/api\.demo\.example/);
 // Value is wrapped in PtInlineCopy
 await app.click(app.all(n=>n.type==='button'&&n.props['aria-label']==='复制资产值')[0]);
 assert.equal(app.copied[0],'demo.example');
});


test('merged FindingsView carries report export and per-item retest actions',async()=>{
 const pentest={assets:[{id:'ast-1',value:'https://demo.example/api'}],nodes:[
   {kind:'finding',id:'finding-1',severity:'high',title:'未授权访问 API',affectedAssetId:'ast-1',description:'接口未校验权限',steps:['执行：curl -i https://demo.example/api，预期返回401']}
 ]};
 const app=setup('FindingsView',{pentest,sessionId:'session-1',t:x=>x});
 assert.equal(app.byTest('pentest-findings').length,1);
 assert.equal(app.byTest('pentest-finding-detail').length,1);
 assert.equal(app.byTest('pentest-report-download').length,1);
 // 切到复测子页签后出现单条一键复测按钮
 const retestTab=app.all(n=>n.type==='button'&&app.text(n)==='复测')[0];
 assert.ok(retestTab,'retest sub-tab exists');
 await app.click(retestTab);
 assert.equal(app.byTest('pentest-retest-one').length,1);
 assert.equal(app.byTest('pentest-current-packets').length,0);
 // 点击一键复测 -> 恰好一次请求 -> 完成后仅该条出现数据包
 const before=app.calls.length;
 const run=app.button('一键复测');
 const pending=run.props.onClick();
 await tick();app.render();
 assert.equal(app.calls.length,before+1);
 assert.match(app.calls.at(-1).url,/retest\/one\?sessionId=session-1/);
 await app.reply(app.calls.length-1,{key:'finding-1',verdict:'open',detail:'仍存在',packets:[{method:'GET',url:'https://demo.example/api',status:200,requestHeaders:{},requestBody:'',responseHeaders:{},responseBody:'{}'}],ranAt:'2026-01-01'});
 await pending;
 assert.equal(app.byTest('pentest-current-packets').length,1);
});
