package report

// reportHTML is the whole document. It deliberately contains no data-bearing
// JavaScript: the script is static, nonce-authorized, and never uses
// innerHTML. Every scan-derived value is interpolated by html/template in its
// own escaping context (text, attribute, URL). No external subresource is
// referenced; the only outbound anchors are official-docs signal URLs.
const reportHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{{.Nonce}}'">
<meta name="referrer" content="no-referrer">
<title>{{.Title}}</title>
<style>
:root{
  --bg:#f7f8fa; --fg:#1b1f24; --muted:#5b6573; --card:#ffffff; --line:#d8dde5;
  --accent:#0b5cad; --code-bg:#eef1f5;
  --warn-bg:#fff4d6; --warn-fg:#6b4b00; --warn-line:#e8c96b;
  --danger-bg:#fde8e8; --danger-fg:#8a1c1c; --danger-line:#e8a3a3;
  --ok-bg:#e6f6ea; --ok-fg:#1e5b2c; --ok-line:#a9d8b5;
  --info-bg:#e8f1fb; --info-fg:#123f6d; --info-line:#a9c7e8;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#11151a; --fg:#e6e9ee; --muted:#9aa6b5; --card:#181e25; --line:#2b3542;
    --accent:#6ab0ff; --code-bg:#222a33;
    --warn-bg:#3a2f10; --warn-fg:#ffd77a; --warn-line:#6b5518;
    --danger-bg:#3a1717; --danger-fg:#ff9b9b; --danger-line:#6b2626;
    --ok-bg:#14301c; --ok-fg:#93e6a8; --ok-line:#275536;
    --info-bg:#12283f; --info-fg:#a9cdf5; --info-line:#264a70;
  }
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:var(--bg); color:var(--fg);
  font:14px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans CJK SC","Microsoft YaHei",sans-serif;
  padding:16px; max-width:1100px; margin:0 auto; overflow-wrap:anywhere;
}
h1{font-size:24px;line-height:1.25;margin:0 0 4px}
h2{font-size:17px;margin:0 0 10px}
h3{font-size:14px;margin:14px 0 6px}
p{margin:6px 0}
a{color:var(--accent);overflow-wrap:anywhere;word-break:break-word}
.sub{color:var(--muted);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin:14px 0}
.banner{padding:10px 12px;border-radius:8px;margin:10px 0;border:1px solid}
.banner strong{font-weight:700}
.warn{background:var(--warn-bg);color:var(--warn-fg);border-color:var(--warn-line)}
.danger{background:var(--danger-bg);color:var(--danger-fg);border-color:var(--danger-line)}
.ok{background:var(--ok-bg);color:var(--ok-fg);border-color:var(--ok-line)}
.info{background:var(--info-bg);color:var(--info-fg);border-color:var(--info-line)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.stat{border:1px solid var(--line);border-radius:8px;padding:8px 10px;background:var(--bg)}
.stat .k{display:block;color:var(--muted);font-size:12px;margin-bottom:2px}
.stat .v{display:block;font-weight:600;font-size:15px}
.big{font-size:20px}
.table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;border:1px solid var(--line);border-radius:8px;margin:8px 0}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:6px 8px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line);overflow-wrap:anywhere;word-break:break-word}
th{background:var(--code-bg);font-weight:600;white-space:nowrap}
tr:last-child td{border-bottom:0}
.path,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;word-break:break-all}
.muted{color:var(--muted)}
.badge{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:0 7px;font-size:12px;line-height:18px;background:var(--bg);margin-right:4px}
.badge.l5{border-color:var(--danger-line);color:var(--danger-fg)}
.badge.l3{border-color:var(--warn-line);color:var(--warn-fg)}
.badge.l0,.badge.l1{border-color:var(--ok-line);color:var(--ok-fg)}
details{border:1px solid var(--line);border-radius:8px;margin:8px 0;padding:0 10px;background:var(--card)}
details>summary{cursor:pointer;padding:8px 2px;font-weight:600}
details.unit>summary{font-weight:500}
details.unit .body{padding-bottom:10px}
details.paged{margin:10px 0}
.topbar{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}
button{font:inherit;padding:5px 10px;border-radius:7px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}
button:hover{border-color:var(--accent)}
nav.toc{display:flex;gap:10px;flex-wrap:wrap;font-size:13px;margin:6px 0 0}
nav.toc a{text-decoration:none}
footer{color:var(--muted);font-size:12px;margin:24px 0 8px;border-top:1px solid var(--line);padding-top:10px}
@media (max-width:480px){
  body{padding:10px}
  h1{font-size:20px}
  h2{font-size:16px}
  th,td{padding:5px 6px}
  .grid{grid-template-columns:repeat(auto-fit,minmax(130px,1fr))}
}
</style>
</head>
<body>
{{if .LAN}}<div class="banner danger" role="alert"><strong>⚠ 此报告服务已暴露到局域网（--lan）。</strong> 任何能访问本机网络地址的设备都可能打开此页。令牌仍在 URL fragment 中，但请尽快关闭服务，且不要把链接转发到聊天工具。</div>{{end}}
{{if .Redacted}}<div class="banner info"><strong>路径已折叠（--redact-paths）。</strong> 绝对路径已折叠为根相对或 ~ 形式；这降低了可识别度，但报告仍含机器信息与凭据位置，可转发性变化：不应视为可公开文件。</div>{{end}}
<header>
  <h1>{{.Title}}</h1>
  <p class="sub">生成于 {{.Generated}} · 机器 {{.Machine}} · scan_id <span class="mono">{{.ScanID}}</span></p>
  <p class="sub">本次选择：{{.SelectionText}}</p>
  <nav class="toc">
    <a href="#summary">摘要</a>
    <a href="#l5">L5 重登清单</a>
    <a href="#unversioned">未版本控制 L2/L3</a>
    <a href="#secrets">凭据位置</a>
    <a href="#reclaim">可再生体积</a>
    <a href="#residual">残留项</a>{{if .HasSkipped}}
    <a href="#skipped">本次未带走</a>{{end}}
    {{if .HasDetails}}<a href="#details">结论与信号</a>{{end}}
    {{if .Notes}}<a href="#notes">扫描说明</a>{{end}}
  </nav>
</header>

<section id="summary" class="card">
  <h2>摘要</h2>
  <div class="grid">
    <div class="stat"><span class="k">扫描时间</span><span class="v">{{.StartedAt}}</span></div>
    <div class="stat"><span class="k">结束时间</span><span class="v">{{.EndedAt}}</span></div>
    <div class="stat"><span class="k">耗时</span><span class="v">{{.Duration}}</span></div>
    <div class="stat"><span class="k">机器</span><span class="v">{{.Machine}}</span></div>
    <div class="stat"><span class="k">完整扫描</span><span class="v">{{.Complete}}</span></div>
    <div class="stat"><span class="k">条目总数</span><span class="v big">{{.TotalUnits}}</span></div>
    <div class="stat"><span class="k">残留数</span><span class="v big">{{.Residuals}}</span></div>
    <div class="stat"><span class="k">可释放体积（分配大小）</span><span class="v big">{{.ReclaimText}}</span></div>
    <div class="stat"><span class="k">工具</span><span class="v">{{.Tool}}</span></div>
  </div>
  <div class="banner warn" role="note">
    <strong>残留项未做内容级密检测。</strong>
    残留项由 catch-all 兜底，只记录存在性、体积与路径，不读取内容；因此“未发现凭据”不代表残留项里没有凭据。这是 D-021 第 7 条要求的固定提示。
  </div>
  <div class="banner {{if .ContainsSecrets}}danger{{else}}ok{{end}}">
    <strong>是否含密：</strong>{{.ContainsText}}<br>
    <strong>可否外发：</strong>否。报告包含本机路径、机器信息与凭据位置；即使使用 --redact-paths，也只能降低可识别度，不能当作可公开或可转发的文件。
    {{if .MayOnlySecrets}}<br><strong>另：</strong>{{.MayOnlySecrets}} 个聚合项声明“可能含密”但未做内容级检测，已与“实际命中”分开统计。{{end}}
  </div>
</section>

<section id="l5" class="card">
  <h2>L5 清单：换机后必须人工重登（{{.L5Count}}）</h2>
  <p class="muted">此类项无法通过打包迁移；即使加密也可能在新机解不开。请按官方路径在新机重新登录，并注意前置设备/条件。</p>
  {{if .L5}}
  <div class="table-wrap">
    <table>
      <thead><tr><th>路径 / 目标</th><th>entry</th><th>profile</th><th>官方路径</th><th>前置设备 / 条件</th><th>置信</th><th>密级</th></tr></thead>
      <tbody>
      {{range .L5}}
        <tr>
          <td class="path">{{.Path}}</td>
          <td class="mono">{{.Entry}}</td>
          <td>{{.Profiles}}</td>
          <td>{{.Official}}{{if .OfficialURL}}<br><span class="mono muted">{{.OfficialURL}}</span>{{end}}</td>
          <td>{{.Prereq}}</td>
          <td class="mono">{{.Confidence}}</td>
          <td><span class="badge l5">{{.Secret}}</span></td>
        </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{else}}<p class="muted">未发现 L5 项。</p>{{end}}
</section>

<section id="unversioned" class="card">
  <h2>未版本控制的 L2/L3（{{.Unversioned}}）</h2>
  <p class="muted">这些路径没有被任何版本库跟踪，却承载配置或会话状态——本产品的核心发现。丢失后无法从远端恢复。</p>
  {{if .UnversionedRows}}
  <div class="table-wrap">
    <table>
      <thead><tr><th>路径</th><th>层</th><th>动作</th><th>entry</th><th>profile</th><th>分配大小</th><th>置信</th><th>risk_flags</th></tr></thead>
      <tbody>
      {{range .UnversionedRows}}
        <tr>
          <td class="path">{{.Path}}</td>
          <td><span class="badge {{.Layer}}">{{.Layer}}</span></td>
          <td class="mono">{{.Action}}</td>
          <td class="mono">{{.Entry}}</td>
          <td>{{.Profiles}}</td>
          <td class="mono">{{.SizeText}}</td>
          <td class="mono">{{.Confidence}}</td>
          <td class="mono">{{.Flags}}</td>
        </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{else}}<p class="muted">未发现未版本控制的 L2/L3 项。</p>{{end}}
</section>

<section id="secrets" class="card">
  <h2>明文凭据位置（{{.SecretHits}} 处）</h2>
  <p class="muted">报告只显示非密前缀掩码与加盐指纹，完整值从不进入报告（manifest 本身也不保存完整值）。manifest 只保存 ≤7 字符的非密前缀，不保存末 4 位，因此掩码列为「前缀…」，绝不合成尾串。指纹用于同一次扫描内对账；跨扫描需 stable salt 才可比。</p>
  {{if .SecretPages}}
  <div class="topbar"><button type="button" id="expand-all">展开全部</button><button type="button" id="collapse-all">折叠全部</button></div>
  {{range .SecretPages}}
  <details class="paged"{{if .Open}} open{{end}}>
    <summary>{{if .Label}}{{.Label}}{{else}}全部条目{{end}}</summary>
    <div class="table-wrap">
      <table>
        <thead><tr><th>路径</th><th>定位</th><th>类型</th><th>分类</th><th>掩码</th><th>指纹</th><th>备注</th></tr></thead>
        <tbody>
        {{range .Rows}}
          <tr>
            <td class="path">{{.Path}}</td>
            <td class="mono">{{.Locator}}</td>
            <td class="mono">{{.Kind}}</td>
            <td class="mono">{{.Class}}</td>
            <td class="mono">{{.Mask}}</td>
            <td class="mono">{{.Fingerprint}}</td>
            <td>{{.Note}}</td>
          </tr>
        {{end}}
        </tbody>
      </table>
    </div>
  </details>
  {{end}}
  {{if .SecretTruncated}}<p class="banner warn">部分条目的命中已截断（manifest 每条最多 32 处），上表不是完整计数。</p>{{end}}
  {{else}}<p class="muted">未在已解析内容中发现凭据。注意：残留项未做内容级密检测。</p>{{end}}
</section>

<section id="reclaim" class="card">
  <h2>可再生体积（L0 / L1）</h2>
  <p class="muted">这些层可在新机重建；重建需下载或重新生成，因此不计入“需要搬运”的体积。</p>
  <div class="grid">
    <div class="stat"><span class="k">L0 可重建（{{.L0Count}} 项）</span><span class="v big">{{.L0Text}}</span></div>
    <div class="stat"><span class="k">L1 可重装（{{.L1Count}} 项，重建需下载）</span><span class="v big">{{.L1Text}}</span></div>
    <div class="stat"><span class="k">proposed_action=delete（{{.DeleteCount}} 项）</span><span class="v big">{{.ReclaimText}}</span></div>
  </div>
  <p class="muted">体积均为分配大小（allocation size），不是逻辑大小；聚合项按 manifest 记录的值计入。</p>
</section>

<section id="residual" class="card">
  <h2>残留项（catch-all，{{.Residuals}}）</h2>
  <p class="banner warn"><strong>残留项未做内容级密检测。</strong> 这些路径没有被任何 profile entry 声明；它们的密级为默认 none/scan，报告不读取内容。</p>
  {{if .ResidualPages}}
  {{range .ResidualPages}}
  <details class="paged"{{if .Open}} open{{end}}>
    <summary>{{if .Label}}{{.Label}}{{else}}全部条目{{end}}</summary>
    <div class="table-wrap">
      <table>
        <thead><tr><th>路径</th><th>层</th><th>动作</th><th>entry</th><th>分配大小</th><th>聚合后代</th><th>置信</th><th>risk_flags</th></tr></thead>
        <tbody>
        {{range .Rows}}
          <tr>
            <td class="path">{{.Path}}</td>
            <td><span class="badge {{.Layer}}">{{.Layer}}</span></td>
            <td class="mono">{{.Action}}</td>
            <td class="mono">{{.Entry}}</td>
            <td class="mono">{{.SizeText}}</td>
            <td class="mono">{{.CountText}}</td>
            <td class="mono">{{.Confidence}}</td>
            <td class="mono">{{.Flags}}</td>
          </tr>
        {{end}}
        </tbody>
      </table>
    </div>
  </details>
  {{end}}
  {{else}}<p class="muted">没有残留项（residual = 0）。</p>{{end}}
</section>

{{if .HasSkipped}}
<section id="skipped" class="card">
  <h2>本次未带走（{{len .SkippedSummary}} 类）</h2>
  <p>下列条目或会话按选择规则被跳过，包与 manifest 里都没有它们的行。用 <span class="mono">--include sessions</span> 或 <span class="mono">--preset full</span> 可打开会话内容。</p>
  <ul>
  {{range .SkippedSummary}}<li>{{.Category}}：{{.Count}} 条</li>{{end}}
  </ul>
  {{if not .ShowSkippedDetails}}<p class="muted">默认选择，不逐条展开；使用 --preset/--include/--exclude 或会话过滤后这里会列出每个 id 与原因。</p>{{end}}
  {{if .SkippedPages}}
  {{range .SkippedPages}}
  <details class="paged"{{if .Open}} open{{end}}>
    <summary>{{if .Label}}{{.Label}}{{else}}全部条目{{end}}</summary>
    <div class="table-wrap">
      <table>
        <thead><tr><th>entry</th><th>类别</th><th>原因</th></tr></thead>
        <tbody>
        {{range .Rows}}
          <tr><td class="mono">{{.Entry}}</td><td>{{.Category}}</td><td>{{.Reason}}</td></tr>
        {{end}}
        </tbody>
      </table>
    </div>
  </details>
  {{end}}
  {{end}}
</section>
{{end}}

{{if .HasDetails}}
<section id="details" class="card">
  <h2>结论与信号（{{len .DetailPages}} 页）</h2>
  <p class="muted">每条结论下列出支撑它的 signals。带链接的条目是官方文档出处，仅在点击时打开，不会自动请求；均带 rel="noopener noreferrer"。</p>
  {{range .DetailPages}}
  <details class="paged"{{if .Open}} open{{end}}>
    <summary>{{if .Label}}{{.Label}}{{else}}全部条目{{end}}</summary>
    {{range .Rows}}
    <details class="unit">
      <summary>
        <span class="badge {{.Layer}}">{{.Layer}}</span>
        <span class="path">{{.Path}}</span>
      </summary>
      <div class="body">
        <p class="sub">
          entry <span class="mono">{{.Entry}}</span>
          · profile {{.Profiles}}
          · action <span class="mono">{{.Action}}</span>
          · confidence <span class="mono">{{.Confidence}}</span>
          · secret <span class="mono">{{.SecretClass}}</span>
          {{if .Flags}}· risk_flags <span class="mono">{{.Flags}}</span>{{end}}
        </p>
        {{if .Signals}}
        <div class="table-wrap">
          <table>
            <thead><tr><th>src</th><th>note</th><th>出处</th></tr></thead>
            <tbody>
            {{range .Signals}}
              <tr>
                <td class="mono">{{.Src}}</td>
                <td>{{.Note}}</td>
                <td>{{if .Link}}<a href="{{.URL}}" rel="noopener noreferrer" target="_blank">{{.URL}}</a>{{else}}—{{end}}</td>
              </tr>
            {{end}}
            </tbody>
          </table>
        </div>
        {{else}}<p class="muted">无信号记录。</p>{{end}}
      </div>
    </details>
    {{end}}
  </details>
  {{end}}
</section>
{{end}}

{{if .Notes}}
<section id="notes" class="card">
  <h2>扫描说明（notes，{{len .Notes}}）</h2>
  <div class="table-wrap">
    <table>
      <thead><tr><th>code</th><th>profile</th><th>entry</th><th>detail</th></tr></thead>
      <tbody>
      {{range .Notes}}
        <tr><td class="mono">{{.Code}}</td><td>{{.Profile}}</td><td class="mono">{{.Entry}}</td><td>{{.Detail}}</td></tr>
      {{end}}
      </tbody>
    </table>
  </div>
</section>
{{end}}

<footer>
  <p>本报告为单文件离线产物：CSS 与 JS 内联，不请求任何外部子资源；出处链接仅在点击时打开。</p>
  <p>packout P0 · 报告只读 manifest · 残留项未做内容级密检测 · 生成于 {{.Generated}}</p>
</footer>
<script nonce="{{.Nonce}}">
(function(){
  "use strict";
  var pages = document.querySelectorAll("details.paged");
  function setAll(open){
    for (var i = 0; i < pages.length; i++) { pages[i].open = open; }
  }
  var expand = document.getElementById("expand-all");
  var collapse = document.getElementById("collapse-all");
  if (expand) { expand.addEventListener("click", function(){ setAll(true); }); }
  if (collapse) { collapse.addEventListener("click", function(){ setAll(false); }); }
  try {
    if (location.search) {
      history.replaceState(null, "", location.pathname + location.hash);
    }
  } catch (e) { /* history is best-effort */ }
})();
</script>
</body>
</html>
`
