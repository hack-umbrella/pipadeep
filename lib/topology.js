// 资产拓扑图 HTML 生成器。
//
// 目的：每次渗透探测到新资产（或新增关联漏洞）时，把当前资产拓扑导出成一份
// **自包含**（无 CDN、离线可开）的交互式 HTML，文件按会话存放，重复生成即覆盖更新。
//
// 数据形状与 `graphFor()`（engagements-routes）一致：{ goal, assets, edges, nodes }。
// 拓扑只取资产节点与 `parent` 边（资产层级），漏洞经 `affectedAssetId` 挂到资产上。
//
// 布局：横向树（深度向右、兄弟向下）+ 容器原生滚动。资产动辄几十上百个，纵向可滚动
// 比"缩放到一屏"实用得多；缩放只用来按需放大/缩小。
import { mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/** 拓扑 HTML 输出目录（可用 PENTEST_TOPOLOGY_DIR 覆盖）。 */
export function topologyRoot() {
	if (typeof process.env.PENTEST_TOPOLOGY_DIR === "string" && process.env.PENTEST_TOPOLOGY_DIR !== "") return process.env.PENTEST_TOPOLOGY_DIR;
	const home = process.env.DSH_HOME || join(homedir(), ".dsh");
	return join(home, "storages", "topology");
}

/** 一个会话的拓扑 HTML 文件路径。 */
export function topologyFile(sessionId) {
	const safe = String(sessionId || "unknown").replace(/[^A-Za-z0-9._-]/g, "_");
	return join(topologyRoot(), safe + ".html");
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

/** 把 `graphFor()` 的图整理成拓扑渲染数据：资产树 + 挂在资产上的漏洞 + 统计。 */
export function buildTopologyData(graph, generatedAt) {
	const goal = graph && graph.goal ? graph.goal : { target: "", objective: "", authorization: "" };
	const sessionId = graph && graph.sessionId ? graph.sessionId : "";
	const assets = Array.isArray(graph && graph.assets) ? graph.assets : [];
	const edges = Array.isArray(graph && graph.edges) ? graph.edges : [];
	const nodes = Array.isArray(graph && graph.nodes) ? graph.nodes : [];
	const findings = nodes.filter((node) => node && node.kind === "finding");
	const assetIds = new Set(assets.map((asset) => asset.id));
	const findingsByAsset = new Map();
	for (const finding of findings) {
		if (typeof finding.affectedAssetId !== "string" || !assetIds.has(finding.affectedAssetId)) continue;
		const bucket = findingsByAsset.get(finding.affectedAssetId) || [];
		bucket.push({ id: finding.id, title: finding.title, severity: finding.severity });
		findingsByAsset.set(finding.affectedAssetId, bucket);
	}
	// 资产层级的父指针：只看 parent 边，且两端都得是资产。
	const parentOf = new Map();
	for (const edge of edges) {
		if (edge.kind !== "parent") continue;
		if (!assetIds.has(edge.sourceId) || !assetIds.has(edge.targetId)) continue;
		if (!parentOf.has(edge.targetId)) parentOf.set(edge.targetId, edge.sourceId);
	}
	const rootId = "__root__";
	const byId = new Map();
	for (const asset of assets) byId.set(asset.id, asset);
	// 父指针指向不存在的资产（或自环/成环）时降级为根的子节点。
	const resolveParent = (asset) => {
		const parent = parentOf.get(asset.id);
		if (parent === undefined || parent === asset.id || !byId.has(parent)) return rootId;
		const seen = new Set([asset.id]);
		let cursor = parent;
		while (cursor !== undefined && cursor !== rootId) {
			if (seen.has(cursor)) return rootId;
			seen.add(cursor);
			cursor = parentOf.get(cursor);
		}
		return parent;
	};
	const childrenOf = new Map([[rootId, []]]);
	for (const asset of assets) childrenOf.set(asset.id, []);
	for (const asset of assets) (childrenOf.get(resolveParent(asset)) || childrenOf.get(rootId)).push(asset.id);
	const nodeList = [{
		id: rootId,
		type: "target",
		value: typeof goal.target === "string" && goal.target !== "" ? goal.target : "（未设置目标）",
		meta: typeof goal.objective === "string" ? goal.objective : "",
		parent: null,
		findings: []
	}];
	for (const asset of assets) {
		nodeList.push({
			id: asset.id,
			type: typeof asset.type === "string" ? asset.type : "endpoint",
			value: typeof asset.value === "string" ? asset.value : "",
			meta: typeof asset.meta === "string" ? asset.meta : "",
			parent: resolveParent(asset),
			findings: findingsByAsset.get(asset.id) || []
		});
	}
	const links = [];
	for (const node of nodeList) if (node.parent !== null) links.push([node.parent, node.id]);
	const byType = {};
	for (const asset of assets) {
		const type = typeof asset.type === "string" ? asset.type : "endpoint";
		byType[type] = (byType[type] || 0) + 1;
	}
	const bySeverity = {};
	for (const finding of findings) {
		const severity = SEVERITY_ORDER.includes(finding.severity) ? finding.severity : "info";
		bySeverity[severity] = (bySeverity[severity] || 0) + 1;
	}
	const children = {};
	for (const [id, kids] of childrenOf) children[id] = kids;
	return {
		sessionId,
		target: nodeList[0].value,
		objective: nodeList[0].meta,
		authorization: typeof goal.authorization === "string" ? goal.authorization : "",
		generatedAt: generatedAt || new Date().toISOString(),
		nodes: nodeList,
		links,
		children,
		findings: findings.map((finding) => ({
			id: finding.id,
			title: finding.title,
			severity: finding.severity,
			affectedAssetId: typeof finding.affectedAssetId === "string" ? finding.affectedAssetId : "",
			description: typeof finding.description === "string" ? finding.description : ""
		})),
		stats: {
			assets: assets.length,
			edges: links.length,
			findings: findings.length,
			byType,
			bySeverity
		}
	};
}

/** 把拓扑数据渲染成一份自包含的 HTML（深色主题、可缩放、可检索、可点选）。 */
export function renderTopologyHtml(data) {
	// 嵌入 JSON 时转义 `<`，避免值里的 `</script>` 提前结束标签。
	const json = JSON.stringify(data).replace(/</g, "\\u003c");
	const title = "资产拓扑 · " + String(data.target || data.sessionId || "pentest");
	return [
		"<!doctype html>",
		'<html lang="zh-CN"><head><meta charset="utf-8">',
		'<meta name="viewport" content="width=device-width, initial-scale=1">',
		"<title>" + esc(title) + "</title>",
		"<style>" + CSS + "</style>",
		"</head><body>",
		'<header id="bar">',
		'<div class="brand"><span class="dot"></span><strong id="target"></strong><span id="meta" class="meta"></span></div>',
		'<div class="tools">',
		'<input id="q" type="search" placeholder="搜索资产 / meta…" autocomplete="off">',
		'<button id="fit" type="button">适应宽度</button>',
		'<button id="zoomin" type="button">＋</button>',
		'<button id="zoomout" type="button">－</button>',
		'<button id="expand" type="button">全部展开</button>',
		"</div>",
		'<div id="stats" class="stats"></div>',
		"</header>",
		'<div id="legend"></div>',
		'<div id="scroller"><svg id="svg" xmlns="http://www.w3.org/2000/svg"><g id="view"></g></svg></div>',
		'<aside id="panel" hidden></aside>',
		'<div id="hint">拖拽平移 · Ctrl/⌘+滚轮 缩放 · 点击节点看详情 · 点击 ▸/▾ 折叠子树</div>',
		'<script id="topo-data" type="application/json">' + json + "</script>",
		"<script>" + CLIENT + "</script>",
		"</body></html>"
	].join("\n");
}

/** 生成并覆盖写盘，返回 { path, data }。 */
export function writeTopologyHtml(sessionId, graph, generatedAt) {
	const data = buildTopologyData(graph, generatedAt);
	const path = topologyFile(sessionId || data.sessionId);
	mkdirSync(topologyRoot(), { recursive: true });
	writeFileSync(path, renderTopologyHtml(data), "utf8");
	return { path, data };
}

function esc(text) {
	return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

const TYPE_COLORS = {
	target: "#7c5cff",
	"root-domain": "#4f9dff",
	subdomain: "#39c5cf",
	ip: "#f0a047",
	service: "#e0607e",
	app: "#59c26b",
	endpoint: "#9aa4b2"
};
const SEVERITY_COLORS = {
	critical: "#ff4d4f",
	high: "#ff8b3d",
	medium: "#f5c542",
	low: "#4f9dff",
	info: "#8a94a6"
};

const CSS = `
:root{--bg:#0e1117;--panel:#151a23;--line:#242c3a;--fg:#e6ebf2;--dim:#8a94a6}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--bg);color:var(--fg);font:13px/1.5 -apple-system,"PingFang SC","Microsoft YaHei",Segoe UI,sans-serif;overflow:hidden}
#bar{position:fixed;inset:0 0 auto 0;z-index:7;display:flex;flex-wrap:wrap;align-items:center;gap:10px;padding:10px 14px;background:rgba(14,17,23,.94);border-bottom:1px solid var(--line);backdrop-filter:blur(8px)}
.brand{display:flex;align-items:center;gap:8px;min-width:0}
.brand .dot{width:9px;height:9px;border-radius:50%;background:#7c5cff;box-shadow:0 0 10px #7c5cff;flex:0 0 auto}
.brand strong{font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:36vw}
.meta{color:var(--dim);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:30vw}
.tools{display:flex;gap:6px;align-items:center;margin-left:auto}
.tools input{background:#0b0e14;border:1px solid var(--line);color:var(--fg);border-radius:7px;padding:5px 9px;width:180px;outline:none}
.tools input:focus{border-color:#4f9dff}
.tools button{background:#1b2230;border:1px solid var(--line);color:var(--fg);border-radius:7px;padding:5px 10px;cursor:pointer;white-space:nowrap}
.tools button:hover{border-color:#4f9dff}
.stats{color:var(--dim);font-size:12px;flex-basis:100%;display:flex;flex-wrap:wrap;gap:12px}
.stats b{color:var(--fg);font-weight:600}
#legend{position:fixed;left:14px;bottom:14px;z-index:4;display:flex;flex-wrap:wrap;gap:8px;max-width:70vw}
.lg{display:flex;align-items:center;gap:5px;background:rgba(21,26,35,.92);border:1px solid var(--line);border-radius:20px;padding:3px 9px;font-size:12px;cursor:pointer;user-select:none}
.lg.off{opacity:.35}
.lg i{width:9px;height:9px;border-radius:3px;display:inline-block}
#scroller{position:fixed;top:96px;left:0;right:0;bottom:0;overflow:auto;z-index:1;cursor:grab}
#scroller.drag{cursor:grabbing}
#svg{display:block;background:
  linear-gradient(rgba(255,255,255,.028) 1px,transparent 1px) 0 0/100% 26px,
  linear-gradient(90deg,rgba(255,255,255,.028) 1px,transparent 1px) 0 0/26px 100%}
.node rect{fill:#151a23;stroke:#3a4658;stroke-width:1.2;rx:9}
.node.sel rect{stroke:#7c5cff;stroke-width:2}
.node.dim{opacity:.2}
.node.hit rect{stroke:#f5c542;stroke-width:2}
.node text{fill:var(--fg);font-size:12px;pointer-events:none}
.node text.meta{fill:var(--dim);font-size:10.5px}
.node .tog{fill:var(--dim);font-size:11px;cursor:pointer;pointer-events:auto}
.edge{fill:none;stroke:#2f3a4d;stroke-width:1.4}
.edge.dim{opacity:.18}
#panel{position:fixed;top:96px;right:0;bottom:0;width:360px;z-index:6;background:var(--panel);border-left:1px solid var(--line);padding:16px 16px 40px;overflow:auto;box-shadow:-12px 0 30px rgba(0,0,0,.45)}
#panel h2{margin:0 0 4px;font-size:15px;word-break:break-all;padding-right:24px}
#panel .tag{display:inline-block;background:#1b2230;border:1px solid var(--line);border-radius:6px;padding:1px 7px;font-size:11px;color:var(--dim);margin:0 6px 8px 0}
#panel h3{margin:14px 0 6px;font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.04em}
#panel ul{margin:0;padding-left:16px}
#panel li{margin:4px 0;word-break:break-word}
#panel .close{position:absolute;top:10px;right:10px;background:none;border:none;color:var(--dim);font-size:18px;cursor:pointer}
.sev{display:inline-block;border-radius:6px;padding:1px 6px;font-size:11px;color:#0e1117;font-weight:600}
#hint{position:fixed;right:14px;bottom:14px;z-index:4;color:var(--dim);font-size:11.5px;background:rgba(14,17,23,.75);padding:2px 6px;border-radius:6px}
`;

// 客户端脚本刻意不用模板字符串，避免与生成器的模板字面量冲突。
const CLIENT = `
(function(){
var DATA=JSON.parse(document.getElementById('topo-data').textContent);
var COLORS=${JSON.stringify(TYPE_COLORS)};
var SEV=${JSON.stringify(SEVERITY_COLORS)};
var SEVORDER=${JSON.stringify(SEVERITY_ORDER)};
var COL=232,ROW=68,NW=176,NH=54,GUTY=24,GUTX=NW/2+18;
document.getElementById('target').textContent=DATA.target||DATA.sessionId;
document.getElementById('meta').textContent=DATA.objective?('· '+DATA.objective):'';
var s=DATA.stats;
var bits=['资产 <b>'+s.assets+'</b>','层级边 <b>'+s.edges+'</b>','漏洞 <b>'+s.findings+'</b>'];
for(var k in s.byType)bits.push('<span style="color:'+(COLORS[k]||'#9aa4b2')+'">'+k+' '+s.byType[k]+'</span>');
for(var i=0;i<SEVORDER.length;i++){var kk=SEVORDER[i];if(s.bySeverity[kk])bits.push('<span style="color:'+SEV[kk]+'">'+kk+' '+s.bySeverity[kk]+'</span>');}
bits.push('生成于 '+new Date(DATA.generatedAt).toLocaleString()+' · 会话 '+DATA.sessionId);
document.getElementById('stats').innerHTML=bits.join(' · ');
var byId={};for(var j=0;j<DATA.nodes.length;j++)byId[DATA.nodes[j].id]=DATA.nodes[j];
var collapsed={};
function kids(id){return (DATA.children[id]||[]).slice();}
function visibleKids(id){return collapsed[id]?[]:kids(id);}
function esc2(t){return String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function cut(t,n){t=String(t==null?'':t);return t.length>n?t.slice(0,n-1)+'…':t;}
function nodeFindings(id){var n=byId[id];return n&&n.findings?n.findings:[];}
function worst(id){var fs=nodeFindings(id),w=-1;for(var i=0;i<fs.length;i++){var idx=SEVORDER.indexOf(fs[i].severity);if(idx<0)idx=SEVORDER.length-1;if(w<0||idx<w)w=idx;}return w;}
var placed=[],size={w:0,h:0},depth=0,leaves=0;
function layout(id,d,out){
var ks=visibleKids(id);var y;
if(ks.length===0){y=leaves*ROW;leaves+=1;}
else{var first=null,last=null;for(var i=0;i<ks.length;i++){var r=layout(ks[i],d+1,out);if(first===null)first=r;last=r;}y=(first+last)/2;}
if(d>depth)depth=d;
out.push({id:id,x:GUTX+d*COL,y:GUTY+y,node:byId[id]});return y;}
function relayout(){leaves=0;depth=0;placed=[];layout('__root__',0,placed);
size.w=GUTX*2+NW+depth*COL;size.h=GUTY*2+NH+Math.max(0,leaves-1)*ROW;}
var view=document.getElementById('view'),svg=document.getElementById('svg'),scroller=document.getElementById('scroller');
var scale=1;
function applySize(){svg.setAttribute('width',Math.round(size.w*scale));svg.setAttribute('height',Math.round(size.h*scale));view.setAttribute('transform','scale('+scale+')');}
function draw(){
var e=[],n=[];
for(var i=0;i<DATA.links.length;i++){
var l=DATA.links[i],a=null,b=null;
for(var p=0;p<placed.length;p++){if(placed[p].id===l[0])a=placed[p];if(placed[p].id===l[1])b=placed[p];}
if(!a||!b)continue;
var x1=a.x+NW/2,x2=b.x-NW/2,mx=(x1+x2)/2;
e.push('<path class="edge" d="M '+x1+' '+a.y+' C '+mx+' '+a.y+' '+mx+' '+b.y+' '+x2+' '+b.y+'"></path>');}
for(var q=0;q<placed.length;q++){
var nd=placed[q].node;if(!nd)continue;
var kd=kids(nd.id).length>0,w=worst(nd.id);
var badge=w>=0?'<circle cx="'+(NW/2-10)+'" cy="'+(-NH/2+10)+'" r="6" fill="'+SEV[SEVORDER[w]]+'"></circle>':'';
n.push('<g class="node" data-id="'+esc2(nd.id)+'" transform="translate('+placed[q].x+','+placed[q].y+')">'
+'<rect x="'+(-NW/2)+'" y="'+(-NH/2)+'" width="'+NW+'" height="'+NH+'" rx="9"></rect>'
+badge
+(kd?'<text class="tog" x="'+(-NW/2+7)+'" y="4">'+(collapsed[nd.id]?'\\u25b8':'\\u25be')+'</text>':'')
+'<text x="'+(-NW/2+(kd?20:11))+'" y="-4">'+esc2(cut(nd.value,24))+'</text>'
+'<text class="meta" x="'+(-NW/2+11)+'" y="14">'+esc2(cut(nd.type+(nd.meta?' \\u00b7 '+nd.meta:''),28))+'</text>'
+'</g>');}
view.innerHTML=e.join('')+n.join('');
applySearch();}
function refit(){relayout();draw();fit(true);}
function fit(reset){
var avail=scroller.clientWidth-40;
var target=Math.min(1,avail/size.w);
scale=Math.max(0.18,Math.min(2.5,target));
applySize();
if(reset){scroller.scrollLeft=0;scroller.scrollTop=0;}
}
scroller.addEventListener('mousedown',function(ev){
if(ev.target.closest&&ev.target.closest('.node'))return;
ev.preventDefault();
var sx=ev.clientX,sy=ev.clientY,ox=scroller.scrollLeft,oy=scroller.scrollTop;
scroller.classList.add('drag');
function mv(e2){scroller.scrollLeft=ox-(e2.clientX-sx);scroller.scrollTop=oy-(e2.clientY-sy);}
function up(){document.removeEventListener('mousemove',mv);document.removeEventListener('mouseup',up);scroller.classList.remove('drag');}
document.addEventListener('mousemove',mv);document.addEventListener('mouseup',up);});
scroller.addEventListener('wheel',function(ev){
if(!ev.ctrlKey&&!ev.metaKey)return;
ev.preventDefault();
zoomBy(ev.deltaY<0?1.12:1/1.12,ev.clientX,ev.clientY);},{passive:false});
function zoomBy(f,cx,cy){
var ns=Math.max(0.18,Math.min(2.5,scale*f));
if(ns===scale)return;
var r=scroller.getBoundingClientRect(),mx=(cx==null?scroller.clientWidth/2:cx-r.left),my=(cy==null?scroller.clientHeight/2:cy-r.top);
var cx2=(scroller.scrollLeft+mx)/scale,cy2=(scroller.scrollTop+my)/scale;
scale=ns;applySize();
scroller.scrollLeft=cx2*scale-mx;scroller.scrollTop=cy2*scale-my;
}
view.addEventListener('click',function(ev){
var g=ev.target.closest?ev.target.closest('.node'):null;if(!g)return;
var id=g.getAttribute('data-id');
if(ev.target.classList&&ev.target.classList.contains('tog')){collapsed[id]=!collapsed[id];refit();return;}
select(id);});
var offTypes={};
function applySearch(){
var q=(document.getElementById('q').value||'').trim().toLowerCase();
var groups=view.querySelectorAll('.node');
for(var i=0;i<groups.length;i++){
var id=groups[i].getAttribute('data-id'),n=byId[id];
var text=((n.value||'')+' '+(n.meta||'')+' '+(n.type||'')).toLowerCase();
var off=!!offTypes[n.type];
var dim=off||(q!==''&&text.indexOf(q)<0);
groups[i].classList.toggle('dim',dim);
groups[i].classList.toggle('hit',q!==''&&!off&&text.indexOf(q)>=0);}
var es=view.querySelectorAll('.edge');for(var x=0;x<es.length;x++)es[x].classList.remove('dim');}
function select(id){
var n=byId[id];if(!n)return;
var fs=nodeFindings(id),ks=kids(id),panel=document.getElementById('panel');
var html='<button class="close" type="button">\\u00d7</button><h2>'+esc2(n.value)+'</h2>'
+'<span class="tag">'+esc2(n.type)+'</span>'+(n.meta?'<span class="tag">'+esc2(n.meta)+'</span>':'');
html+='<h3>标识</h3><div style="color:var(--dim);word-break:break-all">'+esc2(n.id)+'</div>';
if(ks.length)html+='<h3>子资产 ('+ks.length+')</h3><ul>'+ks.map(function(kk){return '<li>'+esc2(byId[kk]?byId[kk].value:kk)+'</li>';}).join('')+'</ul>';
if(fs.length)html+='<h3>关联漏洞 ('+fs.length+')</h3><ul>'+fs.map(function(f){return '<li><span class="sev" style="background:'+SEV[f.severity]+'">'+esc2(f.severity)+'</span> '+esc2(f.title)+'</li>';}).join('')+'</ul>';
else html+='<h3>关联漏洞</h3><div style="color:var(--dim)">无</div>';
panel.innerHTML=html;panel.hidden=false;
panel.querySelector('.close').onclick=function(){panel.hidden=true;};
var gs=view.querySelectorAll('.node');for(var i=0;i<gs.length;i++)gs[i].classList.toggle('sel',gs[i].getAttribute('data-id')===id);
}
var types={};for(var t=0;t<DATA.nodes.length;t++)types[DATA.nodes[t].type]=(types[DATA.nodes[t].type]||0)+1;
var lgd=document.getElementById('legend');
Object.keys(types).forEach(function(ty){
var el=document.createElement('div');el.className='lg';el.setAttribute('data-type',ty);
el.innerHTML='<i style="background:'+(COLORS[ty]||'#9aa4b2')+'"></i>'+ty+' <span style="color:var(--dim)">'+types[ty]+'</span>';
el.onclick=function(){offTypes[ty]=!offTypes[ty];el.classList.toggle('off',!!offTypes[ty]);applySearch();};
lgd.appendChild(el);});
document.getElementById('q').addEventListener('input',applySearch);
document.getElementById('fit').onclick=function(){fit(false);};
document.getElementById('zoomin').onclick=function(){zoomBy(1.2,null,null);};
document.getElementById('zoomout').onclick=function(){zoomBy(1/1.2,null,null);};
document.getElementById('expand').onclick=function(){collapsed={};refit();};
window.addEventListener('resize',function(){applySize();});
refit();
})();
`;
