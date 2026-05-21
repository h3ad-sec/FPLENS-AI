// FPLENS-AI — False Positive Analyzer

const PROVIDERS = {
  anthropic: { name:'Claude', defaultModel:'claude-sonnet-4-6',      storageKey:'fplens_key_anthropic', modelKey:'fplens_model_anthropic' },
  openai:    { name:'GPT',    defaultModel:'gpt-4o',                  storageKey:'fplens_key_openai',   modelKey:'fplens_model_openai'   },
  gemini:    { name:'Gemini', defaultModel:'gemini-2.0-flash',        storageKey:'fplens_key_gemini',   modelKey:'fplens_model_gemini'   },
  groq:      { name:'Groq',   defaultModel:'llama-3.3-70b-versatile', storageKey:'fplens_key_groq',    modelKey:'fplens_model_groq'    }
};
const PROVIDER_KEY = 'fplens_active_provider';

const SYSTEM_PROMPT = `You are an L3 SOC detection engineer specializing in false positive analysis and rule tuning.
CRITICAL: Return ONLY raw JSON. No markdown fences, no preamble, no explanation. Invalid JSON breaks the tool.

INPUT TYPE — auto-detect and adapt your analysis:
- Alert name only (e.g., "Suspicious PowerShell Encoded Command"): Infer the detection logic this alert implies. Analyze what legitimate activity would trigger a rule with this name.
- Alert details / description: Extract the core detection conditions. Analyze FPs based on what the alert evaluates.
- Detection rule (KQL, SPL, Sigma, XQL): Base analysis directly on the rule logic provided.
- Raw log events / sample logs: Identify the pattern a detection rule would match in these events. Analyze FPs for that detection.
- Threat scenario description: Identify legitimate behaviors that overlap with the attacker behavior described. Analyze FPs for a detection rule covering this scenario.

STRICT DATA DISCIPLINE:
- Base FP analysis strictly on the actual input — no generic advice ungrounded in the input
- Suggested exclusions: if a rule is provided, match its query language exactly; otherwise write pseudo-conditions that capture the exclusion intent
- Only flag FP scenarios plausible given the input
- TP signals must be specific and observable, directly tied to the input
- FP risk level: HIGH = fires constantly on benign activity; MEDIUM = regular FP noise expected; LOW = well-scoped
- No filler, no generic SOC advice, no em dashes. Short, precise, active voice.

Return JSON with exactly these six keys:
{
  "fp_risk_level": "HIGH or MEDIUM or LOW",
  "fp_risk_summary": "2-3 sentences on why this detection has this FP risk level, grounded in the specific input.",
  "fp_patterns": [
    { "scenario": "Specific legitimate activity that would trigger this detection", "signals": "Observable indicators that identify this hit as a FP" }
  ],
  "tp_signals": ["Specific observable indicator confirming a hit is malicious — directly derivable from the input"],
  "suggested_exclusions": ["Condition or filter to add as exclusion — match the rule's query language if provided, otherwise pseudo-condition. Be specific."],
  "tuning_guidance": ["Specific actionable recommendation to reduce FP noise — e.g., add thresholds, scope to asset groups, add entity allowlisting"]
}
Write 3-6 FP patterns, 3-5 TP signals, 2-4 exclusions, 2-4 tuning items.`;

let activeProvider = localStorage.getItem(PROVIDER_KEY) || 'anthropic';
let currentResult  = null;

async function callAI(userMessage) {
  const p      = PROVIDERS[activeProvider];
  const apiKey = localStorage.getItem(p.storageKey) || '';
  const model  = localStorage.getItem(p.modelKey) || p.defaultModel;
  if (!apiKey) throw new Error('No API key set for ' + p.name + '. Click ⚙ to add your key.');

  if (activeProvider === 'anthropic') {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'x-api-key':apiKey, 'anthropic-version':'2023-06-01', 'anthropic-dangerous-direct-browser-access':'true' },
      body: JSON.stringify({ model, max_tokens:2500, system:SYSTEM_PROMPT, messages:[{role:'user',content:userMessage}] })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error?.message || r.statusText);
    return d.content[0].text;
  }
  if (activeProvider === 'openai') {
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'Authorization':'Bearer '+apiKey },
      body: JSON.stringify({ model, max_tokens:2500, messages:[{role:'system',content:SYSTEM_PROMPT},{role:'user',content:userMessage}] })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error?.message || r.statusText);
    return d.choices[0].message.content;
  }
  if (activeProvider === 'gemini') {
    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify({ contents:[{parts:[{text:SYSTEM_PROMPT+'\n\n'+userMessage}]}], generationConfig:{maxOutputTokens:2500} })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error?.message || r.statusText);
    return d.candidates[0].content.parts[0].text;
  }
  if (activeProvider === 'groq') {
    const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'Authorization':'Bearer '+apiKey },
      body: JSON.stringify({ model, max_tokens:2500, messages:[{role:'system',content:SYSTEM_PROMPT},{role:'user',content:userMessage}] })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error?.message || r.statusText);
    return d.choices[0].message.content;
  }
}

function parseJSON(raw) {
  let s = raw.trim();
  s = s.replace(/^```(?:json)?\n?/i,'').replace(/\n?```$/,'');
  return JSON.parse(s);
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function makeCard(icon, title, bodyHTML) {
  return `<div class="section-card">
    <div class="section-header" onclick="this.closest('.section-card').classList.toggle('collapsed')">
      <div class="section-title"><span class="section-icon">${icon}</span>${esc(title)}</div>
      <div class="section-actions">
        <button class="copy-btn" onclick="event.stopPropagation();copyCard(this)">⧉ Copy</button>
        <span class="collapse-icon">▾</span>
      </div>
    </div>
    <div class="section-body">${bodyHTML}</div>
  </div>`;
}

function renderRiskSummary(level, summary) {
  const cls = level==='HIGH'?'fp-risk-high':level==='MEDIUM'?'fp-risk-medium':'fp-risk-low';
  return `<div class="fp-risk-header">
    <span class="fp-risk-badge ${cls}">${esc(level)} FP RISK</span>
  </div>
  <p class="summary-text">${esc(summary)}</p>`;
}

function renderFPPatterns(patterns) {
  if (!patterns?.length) return '';
  return patterns.map(p => `
    <div class="fp-pattern-item">
      <div class="fp-pattern-scenario">${esc(p.scenario)}</div>
      <div class="fp-pattern-signals">Signals: ${esc(p.signals)}</div>
    </div>`).join('');
}

function renderTPSignals(signals) {
  if (!signals?.length) return '';
  return signals.map(s => `
    <div class="tp-signal-item">
      <span class="tp-dot"></span>
      <span style="font-size:var(--fs-sm);line-height:1.6;">${esc(s)}</span>
    </div>`).join('');
}

function renderExclusions(items) {
  if (!items?.length) return '';
  return items.map(ex => `<div class="exclusion-item">${esc(ex)}</div>`).join('');
}

function renderTuning(items) {
  if (!items?.length) return '';
  return items.map(t => `<div class="tuning-item">${esc(t)}</div>`).join('');
}

function renderOutput(result) {
  currentResult = result;
  const ruleEl = document.getElementById('rule-input');
  const preview = (ruleEl.value||'').trim().slice(0,50);
  document.getElementById('output-title').textContent = preview + (preview.length>=50?'…':'');
  const c = document.getElementById('cards-container');
  c.innerHTML = [
    makeCard('○', 'FP Risk Assessment',    renderRiskSummary(result.fp_risk_level, result.fp_risk_summary)),
    makeCard('○', 'False Positive Patterns', renderFPPatterns(result.fp_patterns)),
    makeCard('◉', 'True Positive Signals',  renderTPSignals(result.tp_signals)),
    makeCard('⌕', 'Suggested Exclusions',   renderExclusions(result.suggested_exclusions)),
    makeCard('◱', 'Tuning Guidance',        renderTuning(result.tuning_guidance))
  ].join('');
}

function copyCard(btn) {
  const body = btn.closest('.section-card').querySelector('.section-body');
  navigator.clipboard.writeText(body.innerText);
  const orig = btn.textContent;
  btn.textContent = '✓';
  setTimeout(() => { btn.textContent = orig; }, 1500);
}

function buildExportText(fmt) {
  if (!currentResult) return '';
  const lines = [];
  const sec = (title, content) => lines.push(fmt==='md' ? `## ${title}\n\n${content}\n` : `=== ${title} ===\n\n${content}\n`);
  sec('FP Risk Assessment', `${currentResult.fp_risk_level} FP RISK\n\n${currentResult.fp_risk_summary}`);
  if (currentResult.fp_patterns?.length) sec('False Positive Patterns', currentResult.fp_patterns.map(p=>`- ${p.scenario}\n  Signals: ${p.signals}`).join('\n\n'));
  if (currentResult.tp_signals?.length)  sec('True Positive Signals',  currentResult.tp_signals.map(s=>`- ${s}`).join('\n'));
  if (currentResult.suggested_exclusions?.length) sec('Suggested Exclusions', currentResult.suggested_exclusions.map(e=>`- ${e}`).join('\n'));
  if (currentResult.tuning_guidance?.length) sec('Tuning Guidance', currentResult.tuning_guidance.map(t=>`- ${t}`).join('\n'));
  return lines.join('\n');
}

// ── DOM
const generateBtn = document.getElementById('generate-btn');
const clearBtn    = document.getElementById('clear-btn');
const ruleInput   = document.getElementById('rule-input');
const loadingEl   = document.getElementById('loading-state');
const errorEl     = document.getElementById('error-state');
const outputEl    = document.getElementById('output-section');

function getActiveKey() { return localStorage.getItem(PROVIDERS[activeProvider].storageKey)||''; }
function updateBtn()    { generateBtn.disabled = !ruleInput.value.trim() || !getActiveKey(); }

generateBtn.addEventListener('click', async () => {
  const rule = ruleInput.value.trim();
  if (!rule) return;
  errorEl.classList.add('hidden');
  outputEl.classList.add('hidden');
  loadingEl.classList.remove('hidden');
  generateBtn.disabled = true;
  try {
    const hits = document.getElementById('sample-hits').value.trim();
    const env  = document.getElementById('env-context').value.trim();
    const msg  = `Input:\n${rule}${hits?'\n\nSample hits / additional logs:\n'+hits:''}${env?'\n\nEnvironment context: '+env:''}`;
    const raw    = await callAI(msg);
    const result = parseJSON(raw);
    loadingEl.classList.add('hidden');
    renderOutput(result);
    outputEl.classList.remove('hidden');
  } catch(e) {
    loadingEl.classList.add('hidden');
    document.getElementById('error-message').textContent = e.message;
    errorEl.classList.remove('hidden');
  } finally { updateBtn(); }
});

clearBtn.addEventListener('click', () => {
  ruleInput.value = '';
  document.getElementById('sample-hits').value = '';
  document.getElementById('env-context').value = '';
  errorEl.classList.add('hidden');
  outputEl.classList.add('hidden');
  updateBtn();
});
ruleInput.addEventListener('input', updateBtn);

document.getElementById('copy-all-btn').addEventListener('click', () => navigator.clipboard.writeText(buildExportText('md')));
document.getElementById('export-btn').addEventListener('click', () => {
  const fmt  = document.querySelector('.export-tab.active')?.dataset.fmt||'md';
  const blob = new Blob([buildExportText(fmt)],{type:'text/plain'});
  const a    = document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=`fplens-${Date.now()}.${fmt}`; a.click();
});
document.querySelectorAll('.export-tab').forEach(t=>t.addEventListener('click',()=>{document.querySelectorAll('.export-tab').forEach(x=>x.classList.remove('active'));t.classList.add('active');}));
document.getElementById('new-btn').addEventListener('click',()=>{outputEl.classList.add('hidden');ruleInput.focus();});

// ── Settings modal
const overlay = document.getElementById('modal-overlay');
document.getElementById('settings-btn').addEventListener('click',()=>{overlay.classList.remove('hidden');loadModal();});
document.getElementById('close-modal').addEventListener('click',()=>overlay.classList.add('hidden'));
overlay.addEventListener('click',e=>{if(e.target===overlay)overlay.classList.add('hidden');});

function loadModal() {
  Object.entries(PROVIDERS).forEach(([id,p])=>{
    const k=document.getElementById('key-'+id); const m=document.getElementById('model-'+id);
    if(k) k.value=localStorage.getItem(p.storageKey)||'';
    if(m) m.value=localStorage.getItem(p.modelKey)||p.defaultModel;
  });
  document.querySelectorAll('.provider-tab').forEach(t=>t.classList.toggle('active',t.dataset.provider===activeProvider));
}
document.getElementById('save-key-btn').addEventListener('click',()=>{
  Object.entries(PROVIDERS).forEach(([id,p])=>{
    const k=document.getElementById('key-'+id); const m=document.getElementById('model-'+id);
    if(k) localStorage.setItem(p.storageKey,k.value.trim());
    if(m) localStorage.setItem(p.modelKey,m.value);
  });
  localStorage.setItem(PROVIDER_KEY,activeProvider);
  overlay.classList.add('hidden');
  updateKeyStatus(); updateBtn(); updateBadge(); updateNotice();
});
document.querySelectorAll('.provider-tab').forEach(tab=>tab.addEventListener('click',()=>{
  activeProvider=tab.dataset.provider;
  document.querySelectorAll('.provider-tab').forEach(t=>t.classList.toggle('active',t.dataset.provider===activeProvider));
}));
document.querySelectorAll('.toggle-key-btn').forEach(btn=>btn.addEventListener('click',()=>{
  const inp=document.getElementById(btn.dataset.target); inp.type=inp.type==='password'?'text':'password';
}));

function updateKeyStatus(){const el=document.getElementById('key-status');const ok=!!getActiveKey();el.textContent=ok?'API Key Set':'No API Key';el.className='key-status '+(ok?'has-key':'no-key');}
function updateBadge(){const b=document.getElementById('active-provider-badge');const names={anthropic:'Claude',openai:'GPT-4o',gemini:'Gemini',groq:'Groq'};b.textContent=names[activeProvider]||activeProvider;b.className='provider-badge '+activeProvider;}
function updateNotice(){const el=document.getElementById('notice-provider');if(el)el.textContent=PROVIDERS[activeProvider]?.name||activeProvider;}

function applyTheme(t){document.body.classList.toggle('light',t==='light');document.body.classList.toggle('dark',t!=='light');const logo=document.getElementById('navLogo');if(logo)logo.src=`https://raw.githubusercontent.com/h3ad-sec/h3ad-sec.github.io/main/logo-${t==='light'?'light':'dark'}.png`;}
applyTheme(localStorage.getItem('h3ad-theme')||'dark');
document.getElementById('theme-toggle').addEventListener('click',()=>{const next=document.body.classList.contains('light')?'dark':'light';localStorage.setItem('h3ad-theme',next);applyTheme(next);});

window.addEventListener('scroll',()=>document.body.classList.toggle('scrolled',window.scrollY>40),{passive:true});
function toggleDrawer(){document.getElementById('navDrawer').classList.toggle('open');}
function closeDrawer(){document.getElementById('navDrawer').classList.remove('open');}

updateKeyStatus(); updateBadge(); updateNotice(); updateBtn(); loadModal();
