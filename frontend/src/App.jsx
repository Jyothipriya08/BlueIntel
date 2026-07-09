import React, { useState, useEffect, useRef } from 'react';
import { 
  LayoutDashboard, Binary, ShieldAlert, FileText, BarChart3, Bot, LogOut, 
  Upload, AlertTriangle, Mail, Lock, Eye, EyeOff, Shield, Terminal, Zap 
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import logoImg from './assets/logo.png';

const threatTimelineData = [
  { date: '07/03', Ransomware: 420, Trojans: 210, ExploitKits: 110 },
  { date: '07/04', Ransomware: 510, Trojans: 180, ExploitKits: 130 },
  { date: '07/05', Ransomware: 480, Trojans: 290, ExploitKits: 90 },
  { date: '07/06', Ransomware: 610, Trojans: 340, ExploitKits: 190 },
  { date: '07/07', Ransomware: 720, Trojans: 410, ExploitKits: 220 },
  { date: '07/08', Ransomware: 890, Trojans: 480, ExploitKits: 310 },
  { date: '07/09', Ransomware: 1040, Trojans: 520, ExploitKits: 450 },
];

export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [authPage, setAuthPage] = useState('login');
  const [activeTab, setActiveTab] = useState('dashboard');
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [authAnimationDirection, setAuthAnimationDirection] = useState('forward');
  const [workspaceAnimationDirection, setWorkspaceAnimationDirection] = useState('right');
  const [transitionState, setTransitionState] = useState('auth');

  // --- STATES FOR HANDLING THE LIVE BACKEND CONNECTION ---
  const [uploading, setUploading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const prevLoggedInRef = useRef(isLoggedIn);
  
  // --- AGENTIC SUPPORT CHAT CONSOLE LOGIC ---
  const [chatInput, setChatInput] = useState('');
  const [chatLog, setChatLog] = useState([
    { role: 'assistant', text: 'System node synchronized. Awaiting instruction on processed indicator payloads.' }
  ]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('auth') === 'success') {
      setIsLoggedIn(true);
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, []);

  useEffect(() => {
    if (!prevLoggedInRef.current && isLoggedIn) {
      setTransitionState('reveal');
      const timer = window.setTimeout(() => setTransitionState('dashboard'), 550);
      return () => window.clearTimeout(timer);
    }
    if (prevLoggedInRef.current && !isLoggedIn) {
      setTransitionState('auth');
    }
    prevLoggedInRef.current = isLoggedIn;
  }, [isLoggedIn]);

  const handleLogin = (e) => {
    e.preventDefault();
    if (email && password) setIsLoggedIn(true);
  };

  const handleSignup = (e) => {
    e.preventDefault();
    alert('Account created! Proceeding to authentication portal.');
    switchAuthPage('login');
  };

  const switchAuthPage = (nextPage) => {
    setAuthAnimationDirection(nextPage === 'signup' ? 'forward' : 'reverse');
    setAuthPage(nextPage);
  };

  const switchTab = (nextTab) => {
    const tabOrder = ['dashboard', 'static_parser', 'dynamic_sandbox', 'ioc_tracker', 'ai_reports', 'threat_graph'];
    const currentIndex = tabOrder.indexOf(activeTab);
    const nextIndex = tabOrder.indexOf(nextTab);
    setWorkspaceAnimationDirection(nextIndex >= currentIndex ? 'right' : 'left');
    setActiveTab(nextTab);
  };

  const handleFileChange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setUploading(true);
    setAnalysisResult(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('http://127.0.0.1:8000/api/v1/upload/', {
        method: 'POST',
        body: formData, 
      });

      if (!response.ok) throw new Error('Analysis engine failure.');

      const data = await response.json();
      setAnalysisResult(data); 

      setChatLog(prev => [...prev, { 
        role: 'assistant', 
        text: `⚠️ Ingested payload [${data.file_name}]. Threat verdict evaluated to ${data.malware_classification?.verdict || 'UNKNOWN'} (${data.malware_classification?.score || 0}/100 score). Compiling Claude AI threat analysis framework...` 
      }]);

      const aiResponse = await fetch('http://127.0.0.1:8000/api/v1/ai-report/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ "analysis_results": data })
      });
      
      if (aiResponse.ok) {
        const aiData = await aiResponse.json();
        setAnalysisResult(prev => ({ ...prev, ai_generated_report: aiData.report }));
        setChatLog(prev => [...prev, { role: 'assistant', text: "🤖 Anthropic intelligence model reporting finalized. Enterprise report ledger mapped to AI tab." }]);
      }
    } catch (error) {
      console.error(error);
      alert('Error connecting to Django security console matrix.');
    } finally {
      setUploading(false);
    }
  };

  const submitAgenticQuery = async (e) => {
    e.preventDefault();
    if (!chatInput.trim()) return;
    const currentQuery = chatInput;
    setChatLog(prev => [...prev, { role: 'user', text: currentQuery }]);
    setChatInput('');

    try {
      const aiResponse = await fetch('http://127.0.0.1:8000/api/v1/ai-report/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          "analysis_results": analysisResult || { "file_name": "No current file active" },
          "query": currentQuery
        })
      });

      if (aiResponse.ok) {
        const aiData = await aiResponse.json();
        setChatLog(prev => [...prev, { role: 'assistant', text: aiData.report }]);
      } else {
        throw new Error();
      }
    } catch (error) {
      setChatLog(prev => [...prev, { role: 'assistant', text: "🤖 Connection error syncing down live query response arrays from endpoint node." }]);
    }
  };

  const renderAuthScreen = () => (
    <div className="min-h-screen w-full bg-[#020212] flex items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute top-1/2 left-1/4 -translate-y-1/2 w-[500px] h-[500px] bg-[#25a5ff]/10 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute top-1/2 right-1/4 -translate-y-1/2 w-[500px] h-[500px] bg-[#25a5ff]/5 rounded-full blur-[140px] pointer-events-none" />

      <div className="backdrop-blur-md bg-gradient-to-b from-[#181d28]/90 to-[#0e121a]/90 p-10 rounded-3xl border border-[#25a5ff]/15 w-full max-w-lg shadow-[0_0_50px_rgba(37,165,255,0.06)] transition-all z-10">
        <div className="text-center mb-6">
          <img src={logoImg} alt="BlueIntel Logo" className="w-24 h-24 mx-auto object-contain mb-2 drop-shadow-[0_0_15px_rgba(37,165,255,0.2)]" />
          <h1 className="text-3xl font-semibold tracking-tight text-white mb-2">{authPage === 'login' ? 'Log in' : 'Sign up'}</h1>
          <p className="text-xs text-[#94a3b8] max-w-sm mx-auto">
            {authPage === 'login' ? 'Log in to your account and seamlessly continue managing your projects.' : 'Create an analyst account to configure local malware rule matrices.'}
          </p>
        </div>

        <div className="relative overflow-hidden">
          <div className={authAnimationDirection === 'forward' ? 'auth-card-enter' : 'auth-card-enter-reverse'}>
            {authPage === 'login' ? (
              <form onSubmit={handleLogin} className="space-y-4">
                <div className="relative">
                  <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575]"><Mail size={18} /></span>
                  <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="w-full bg-[#0a0d14]/60 border border-[#25a5ff]/20 rounded-2xl pl-12 pr-4 py-4 text-white text-sm focus:border-[#25a5ff] outline-none" placeholder="Enter your email address" required />
                </div>
                <div className="relative">
                  <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575]"><Lock size={18} /></span>
                  <input type={showPassword ? "text" : "password"} value={password} onChange={(e) => setPassword(e.target.value)} className="w-full bg-[#0a0d14]/60 border border-[#25a5ff]/20 rounded-2xl pl-12 pr-12 py-4 text-white text-sm focus:border-[#25a5ff] outline-none" placeholder="Enter your password" required />
                  <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-4 top-1/2 -translate-y-1/2 text-[#576575] hover:text-[#25a5ff]"><Eye size={18} /></button>
                </div>
                
                <button type="submit" className="w-full bg-[#1c212c] border border-[#333e54] text-white font-medium py-4 rounded-2xl text-base cursor-pointer hover:bg-[#232936] transition-all">
                  Log in
                </button>

                <div className="grid grid-cols-1 gap-3 pt-2">
                  <button 
                    type="button" 
                    onClick={() => window.location.href = 'http://127.0.0.1:8000/accounts/google/login/'}
                    className="bg-[#131722]/80 hover:bg-[#1a1f2e] border border-[#25a5ff]/30 text-sm py-3.5 rounded-xl text-white shadow-md transition cursor-pointer font-semibold text-center flex items-center justify-center gap-2"
                  >
                    Sign in with Federated Google OAuth2
                  </button>
                </div>

                <p className="text-center text-xs text-[#64748b] pt-4">Didn't have an account? <button type="button" onClick={() => switchAuthPage('signup')} className="text-[#25a5ff] font-medium">Sign up</button></p>
              </form>
            ) : (
              <form onSubmit={handleSignup} className="space-y-4">
                <div className="relative">
                  <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575]"><Mail size={18} /></span>
                  <input type="email" className="w-full bg-[#0a0d14]/60 border border-[#25a5ff]/20 rounded-2xl pl-12 pr-4 py-4 text-white text-sm focus:border-[#25a5ff] outline-none" placeholder="Enter corporate email address" required />
                </div>
                <button type="submit" className="w-full bg-[#1c212c] border border-[#333e54] text-white font-medium py-4 rounded-2xl text-base cursor-pointer hover:bg-[#232936] transition-all">Sign up</button>
                <p className="text-center text-xs text-[#64748b] pt-4">Already authorized? <button type="button" onClick={() => switchAuthPage('login')} className="text-[#25a5ff] font-medium">Log in</button></p>
              </form>
            )}
          </div>
        </div>
      </div>
    </div>
  );

  const renderDashboardScreen = () => (
    <div className="min-h-screen w-full bg-[#020212] flex text-white font-sans relative overflow-hidden">
      <aside className="w-72 bg-gradient-to-b from-[#0e121a] to-[#07090f] border-r border-[#25a5ff]/10 flex flex-col justify-between p-5 z-10">
        <div>
          <div className="flex items-center space-x-3 mb-10 mt-2 px-1">
            <img src={logoImg} alt="BlueIntel" className="w-9 h-9 object-contain drop-shadow-[0_0_8px_rgba(37,165,255,0.3)]" />
            <div className="flex flex-col">
              <span className="font-bold text-md tracking-wider text-white">BLUE<span className="text-[#25a5ff]">INTEL</span></span>
              <span className="text-[9px] tracking-widest uppercase text-[#576575] mt-0.5 font-bold">Threat Matrix Platform</span>
            </div>
          </div>

          {/* --- NUMBERS REMOVED CLEANLY FROM LABELS --- */}
          <nav className="space-y-1.5">
            <button onClick={() => switchTab('dashboard')} className={`w-full flex items-center space-x-3 px-4 py-3.5 rounded-xl text-xs uppercase font-bold tracking-wider cursor-pointer transition ${activeTab === 'dashboard' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926]'}`}><LayoutDashboard size={16} /><span>Triage Dashboard</span></button>
            <button onClick={() => switchTab('static_parser')} className={`w-full flex items-center space-x-3 px-4 py-3.5 rounded-xl text-xs uppercase font-bold tracking-wider cursor-pointer transition ${activeTab === 'static_parser' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926]'}`}><Binary size={16} /><span>Static Analysis</span></button>
            <button onClick={() => switchTab('dynamic_sandbox')} className={`w-full flex items-center space-x-3 px-4 py-3.5 rounded-xl text-xs uppercase font-bold tracking-wider cursor-pointer transition ${activeTab === 'dynamic_sandbox' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926]'}`}><ShieldAlert size={16} /><span>Dynamic Sandbox</span></button>
            <button onClick={() => switchTab('ioc_tracker')} className={`w-full flex items-center space-x-3 px-4 py-3.5 rounded-xl text-xs uppercase font-bold tracking-wider cursor-pointer transition ${activeTab === 'ioc_tracker' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926]'}`}><FileText size={16} /><span>Indicators (IoCs)</span></button>
            <button onClick={() => switchTab('ai_reports')} className={`w-full flex items-center space-x-3 px-4 py-3.5 rounded-xl text-xs uppercase font-bold tracking-wider cursor-pointer transition ${activeTab === 'ai_reports' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926]'}`}><Bot size={16} /><span>AI Reports & Agent</span></button>
            <button onClick={() => switchTab('threat_graph')} className={`w-full flex items-center space-x-3 px-4 py-3.5 rounded-xl text-xs uppercase font-bold tracking-wider cursor-pointer transition ${activeTab === 'threat_graph' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926]'}`}><BarChart3 size={16} /><span>Real-World Graph</span></button>
          </nav>
        </div>

        <div className="border-t border-[#25a5ff]/10 pt-4 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-full bg-[#25a5ff]/10 text-[#25a5ff] flex items-center justify-center text-xs font-bold border border-[#25a5ff]/20">L3</div>
            <div>
              <p className="text-xs font-bold text-white">Operator-Jyothi</p>
              <p className="text-[9px] text-[#576575] uppercase font-bold tracking-wider">SecOps Lead</p>
            </div>
          </div>
          <button onClick={() => setIsLoggedIn(false)} className="text-[#94a3b8] hover:text-red-400 p-2 rounded-xl hover:bg-red-500/10"><LogOut size={16} /></button>
        </div>
      </aside>

      <main className="flex-1 p-8 overflow-y-auto z-10 relative">
        <header className="mb-8 flex justify-between items-center border-b border-[#25a5ff]/10 pb-5">
          <div>
            <h2 className="text-2xl font-bold tracking-wider text-white uppercase">{activeTab.replace('_', ' ')} Module</h2>
            <p className="text-xs text-[#94a3b8] mt-1">Autonomous threat intelligence console terminal matrix configuration layout node.</p>
          </div>
          <div className="bg-[#131926]/80 border border-[#25a5ff]/20 text-[10px] px-4 py-2 rounded-xl text-[#25a5ff] font-mono font-bold uppercase tracking-widest flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#25a5ff] animate-pulse" /> Core System Array: Active
          </div>
        </header>

        <div className="relative overflow-hidden">
          {activeTab === 'dashboard' && (
            <div key={activeTab} className={workspaceAnimationDirection === 'right' ? 'workspace-panel-enter' : 'workspace-panel-enter-left'}>
              <div className="space-y-6">
                <label className="border border-dashed border-[#25a5ff]/30 bg-gradient-to-b from-[#131926]/40 to-[#0e121a]/40 hover:border-[#25a5ff]/60 transition rounded-2xl p-14 text-center flex flex-col items-center justify-center cursor-pointer group block">
                  <input type="file" onChange={handleFileChange} className="hidden" disabled={uploading} />
                  <div className="w-14 h-14 rounded-full bg-[#25a5ff]/5 text-[#25a5ff] flex items-center justify-center mb-4 border border-[#25a5ff]/20">
                    <Upload size={24} />
                  </div>
                  <h3 className="text-base font-semibold text-white mb-1">
                    {uploading ? 'Processing Core Analysis Engine Pipeline...' : 'Ingest Malware Payload Asset File'}
                  </h3>
                  <p className="text-xs text-[#94a3b8] max-w-sm mb-4">Select binaries, portable executable files, or rule metadata code files to analyze.</p>
                  {!uploading && <span className="bg-[#1c212c] border border-[#333e54] text-[#25a5ff] font-bold px-4 py-2 rounded-xl text-xs uppercase tracking-wider">Browse Target Files</span>}
                </label>

                {analysisResult ? (
                  <div className="bg-gradient-to-br from-[#1a1015]/60 to-[#0e121a]/90 border border-red-500/20 p-6 rounded-2xl space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="font-bold tracking-wide uppercase text-xs text-red-400 flex items-center gap-2"><AlertTriangle size={16}/> Active Threat Classification Ingested</span>
                      <span className="font-mono font-bold text-sm px-3 py-1 bg-red-500/20 border border-red-500/30 text-red-400 rounded-lg">{analysisResult.malware_classification?.verdict}</span>
                    </div>
                    <p className="text-sm font-mono text-white mt-2">Target Binary File Asset: <span className="text-[#25a5ff] font-bold">{analysisResult.file_name}</span></p>
                    <p className="text-xs text-[#94a3b8]">Head over to the specialized features tabs on the sidebar view column to analyze specific static telemetry, view hardcoded network IOC lists, or interact with the agentic remediation report generator.</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-2">
                    <div className="bg-[#131926]/40 border border-[#25a5ff]/10 rounded-2xl p-5 flex items-center space-x-4">
                      <div className="p-3 bg-[#25a5ff]/10 text-[#25a5ff] rounded-xl"><FileText size={20} /></div>
                      <div><h4 className="text-2xl font-bold font-mono">1,402</h4><p className="text-[10px] text-[#576575] font-bold uppercase tracking-wider">Total Ingested Scans</p></div>
                    </div>
                    <div className="bg-[#131926]/40 border border-[#25a5ff]/10 rounded-2xl p-5 flex items-center space-x-4">
                      <div className="p-3 bg-red-500/10 text-red-400 rounded-xl"><ShieldAlert size={20} /></div>
                      <div><h4 className="text-2xl font-bold font-mono text-red-400">84</h4><p className="text-[10px] text-[#576575] font-bold uppercase tracking-wider">Critical Matches</p></div>
                    </div>
                    <div className="bg-[#131926]/40 border border-[#25a5ff]/10 rounded-2xl p-5 flex items-center space-x-4">
                      <div className="p-3 bg-emerald-500/10 text-emerald-400 rounded-xl"><Shield size={20} /></div>
                      <div><h4 className="text-2xl font-bold font-mono text-emerald-400">94.01%</h4><p className="text-[10px] text-[#576575] font-bold uppercase tracking-wider">Engine Capture Rate</p></div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'static_parser' && (
            <div key={activeTab} className={workspaceAnimationDirection === 'right' ? 'workspace-panel-enter' : 'workspace-panel-enter-left'}>
              {analysisResult ? (
                <div className="bg-[#131926]/80 border border-[#25a5ff]/15 rounded-2xl p-6 space-y-6">
                  <h3 className="text-sm font-bold uppercase tracking-wider text-[#25a5ff] flex items-center gap-2"><Binary size={18}/> Structural Metadata & Core Fingerprints</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                    <div className="bg-[#020212]/70 p-4 rounded-xl border border-[#25a5ff]/5">
                      <p className="text-[#576575] font-bold uppercase text-[10px]">SHA-256 Signature Registry</p>
                      <p className="text-[#25a5ff] mt-1 break-all">{analysisResult.sha256}</p>
                    </div>
                    <div className="bg-[#020212]/70 p-4 rounded-xl border border-[#25a5ff]/5">
                      <p className="text-[#576575] font-bold uppercase text-[10px]">MD5 Signature Registry</p>
                      <p className="text-white mt-1 break-all">{analysisResult.hashes?.md5 || 'N/A'}</p>
                    </div>
                    <div className="bg-[#020212]/70 p-4 rounded-xl border border-[#25a5ff]/5">
                      <p className="text-[#576575] font-bold uppercase text-[10px]">Shannon Binary Entropy Score</p>
                      <p className="text-lg font-bold text-orange-400 mt-1">{analysisResult.entropy}</p>
                    </div>
                    <div className="bg-[#020212]/70 p-4 rounded-xl border border-[#25a5ff]/5">
                      <p className="text-[#576575] font-bold uppercase text-[10px]">PE File Header Execution Subsystem</p>
                      <p className="text-white mt-1">{analysisResult.is_pe ? `🟢 Windows Binary (EntryPoint: ${analysisResult.pe_metadata?.entry_point})` : '⚪ Non-PE Payload Structure'}</p>
                    </div>
                  </div>

                  {analysisResult.yara_matches && (
                    <div className="bg-[#020212]/50 p-5 rounded-xl border border-[#25a5ff]/5">
                      <p className="text-[#576575] font-semibold uppercase text-[11px] tracking-wider mb-2">YARA Rules Triggered</p>
                      {analysisResult.yara_matches.length > 0 ? (
                        <div className="space-y-2">
                          {analysisResult.yara_matches.map((rule, idx) => (
                            <div key={idx} className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-2 rounded-xl flex items-center gap-2 font-mono text-xs font-bold">
                              <AlertTriangle size={14} /> CRITICAL MATCH: {rule}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-emerald-400 font-mono text-sm font-semibold">🟢 No malicious signatures triggered.</p>
                      )}
                    </div>
                  )}

                  {analysisResult.pe_metadata?.sections && (
                    <div className="space-y-2">
                      <p className="text-[10px] font-bold uppercase tracking-wider text-[#576575]">Dissected Executable PE Headers Section Blocks</p>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
                        {analysisResult.pe_metadata.sections.map((sec, idx) => (
                          <div key={idx} className="bg-black/30 border border-[#25a5ff]/10 p-3 rounded-xl">
                            <p className="text-[#25a5ff] font-bold">{sec.name || '.unnamed'}</p>
                            <p className="text-[10px] text-[#576575] mt-1">Raw Size: {sec.raw_data_size}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : <p className="text-sm font-mono text-[#576575] italic p-6 border border-dashed border-[#25a5ff]/10 rounded-2xl">Awaiting threat payload ingestion data array on Triage Dashboard view.</p>}
            </div>
          )}

          {activeTab === 'dynamic_sandbox' && (
            <div key={activeTab} className={workspaceAnimationDirection === 'right' ? 'workspace-panel-enter' : 'workspace-panel-enter-left'}>
              {analysisResult ? (
                <div className="bg-[#131926]/80 border border-[#25a5ff]/15 rounded-2xl p-6 space-y-4">
                  <h3 className="text-sm font-bold uppercase tracking-wider text-orange-400 flex items-center gap-2"><ShieldAlert size={18}/> Automated Sandboxed Detonation Telemetry</h3>
                  <p className="text-xs text-[#94a3b8] font-sans">Simulating programmatic orchestration deployment sequence environment nodes for <span className="text-white font-mono font-bold">{analysisResult.file_name}</span>...</p>
                  <div className="bg-black/50 p-4 rounded-xl border border-[#25a5ff]/10 font-mono text-xs text-[#25a5ff] space-y-1.5 shadow-inner">
                    <p className="text-[#576575]">[07/09/2026 - Booting Clean Windows Security Detonation Box Instance...]</p>
                    <p>✔ Process Spawned Success: Thread ID 4082 mapped.</p>
                    <p>✔ API Hook Intercepted: LoadLibraryA called tracking system kernel modifications.</p>
                    {analysisResult.iocs?.registry_keys?.length > 0 ? (
                      <p className="text-red-400">⚠ Outbound Mutation: File attempted background write access adjustments to persistent authorization keys.</p>
                    ) : <p className="text-emerald-400">✔ Outbound Mutation: Registry runtime structures remain clear of standard persistency indicators.</p>}
                    <p className="text-orange-400">✔ Detonation Sequence Closed. Dump registry finalized cleanly.</p>
                  </div>
                </div>
              ) : <p className="text-sm font-mono text-[#576575] italic p-6 border border-dashed border-[#25a5ff]/10 rounded-2xl">Awaiting threat payload ingestion data array on Triage Dashboard view.</p>}
            </div>
          )}

          {activeTab === 'ioc_tracker' && (
            <div key={activeTab} className={workspaceAnimationDirection === 'right' ? 'workspace-panel-enter' : 'workspace-panel-enter-left'}>
              {analysisResult?.iocs ? (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="bg-[#131926]/80 border border-[#25a5ff]/10 p-5 rounded-2xl">
                    <p className="text-[#25a5ff] font-bold uppercase text-xs tracking-wider mb-3">Extracted C2 Network IPs</p>
                    {analysisResult.iocs.ips?.length > 0 ? (
                      <div className="space-y-2">{analysisResult.iocs.ips.map((ip, i) => <p key={i} className="font-mono text-xs text-red-400 bg-red-500/5 px-3 py-2 rounded-xl border border-red-500/20">{ip}</p>)}</div>
                    ) : <p className="text-xs text-[#576575] italic font-mono">No host IPs discovered</p>}
                  </div>
                  <div className="bg-[#131926]/80 border border-[#25a5ff]/10 p-5 rounded-2xl">
                    <p className="text-[#25a5ff] font-bold uppercase text-xs tracking-wider mb-3">Extracted Callout Domains</p>
                    {analysisResult.iocs.domains?.length > 0 ? (
                      <div className="space-y-2">{analysisResult.iocs.domains.map((dom, i) => <p key={i} className="font-mono text-xs text-red-400 bg-red-500/5 px-3 py-2 rounded-xl border border-red-500/20 break-all">{dom}</p>)}</div>
                    ) : <p className="text-xs text-[#576575] italic font-mono">No network domains discovered</p>}
                  </div>
                  <div className="bg-[#131926]/80 border border-[#25a5ff]/10 p-5 rounded-2xl">
                    <p className="text-[#25a5ff] font-bold uppercase text-xs tracking-wider mb-3">Registry Persistence Identifiers</p>
                    {analysisResult.iocs.registry_keys?.length > 0 ? (
                      <div className="space-y-2">{analysisResult.iocs.registry_keys.map((reg, i) => <p key={i} className="font-mono text-[11px] text-orange-400 bg-orange-500/5 px-3 py-2 rounded-xl border border-orange-500/20 break-all">{reg}</p>)}</div>
                    ) : <p className="text-xs text-[#576575] italic font-mono">No registry persistence signatures</p>}
                  </div>
                </div>
              ) : <p className="text-sm font-mono text-[#576575] italic p-6 border border-dashed border-[#25a5ff]/10 rounded-2xl">Awaiting threat payload ingestion data array on Triage Dashboard view.</p>}
            </div>
          )}

          {activeTab === 'ai_reports' && (
            <div key={activeTab} className={workspaceAnimationDirection === 'right' ? 'workspace-panel-enter' : 'workspace-panel-enter-left'}>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
                <div className="bg-[#131926]/80 border border-[#25a5ff]/15 p-6 rounded-2xl space-y-4">
                  <h3 className="text-sm font-bold uppercase tracking-wider text-[#25a5ff] flex items-center gap-2"><Zap size={16}/> Generated Executive Risk Summary</h3>
                  {analysisResult ? (
                    <div className="text-xs font-sans text-[#94a3b8] space-y-3 leading-relaxed whitespace-pre-line">
                      {analysisResult.ai_generated_report ? (
                        analysisResult.ai_generated_report
                      ) : (
                        <p className="font-mono text-[#25a5ff] animate-pulse">🤖 Orchestrating Anthropic Claude intelligence engine... Building live analytical summary ledger...</p>
                      )}
                    </div>
                  ) : <p className="text-xs font-mono text-[#576575] italic">Please load a binary file inside the dashboard setup workspace container node first.</p>}
                </div>

                <div className="bg-[#0b0f19] border border-[#25a5ff]/15 rounded-2xl flex flex-col h-[480px] overflow-hidden shadow-2xl">
                  <div className="bg-[#131926] px-4 py-3 border-b border-[#25a5ff]/10 flex items-center gap-2 text-xs font-bold tracking-wider uppercase text-white">
                    <Terminal size={14} className="text-[#25a5ff]"/> Agentic Co-Pilot Support Node
                  </div>
                  <div className="flex-1 p-4 overflow-y-auto space-y-3 text-xs">
                    {chatLog.map((msg, index) => (
                      <div key={index} className={`p-3 rounded-xl max-w-[85%] font-mono whitespace-pre-line ${msg.role === 'user' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20 ml-auto' : 'bg-white/5 text-[#94a3b8] mr-auto'}`}>
                        <p className="text-[10px] uppercase tracking-wider opacity-40 font-bold mb-1">{msg.role === 'user' ? 'Operator' : 'BlueIntel Agent'}</p>
                        {msg.text}
                      </div>
                    ))}
                  </div>
                  <form onSubmit={submitAgenticQuery} className="p-3 bg-[#131926] border-t border-[#25a5ff]/10 flex gap-2">
                    <input type="text" value={chatInput} onChange={(e) => setChatInput(e.target.value)} className="flex-1 bg-[#020212] border border-[#25a5ff]/20 rounded-xl px-4 py-2.5 text-xs text-white outline-none focus:border-[#25a5ff]" placeholder="Ask about remediation, ioc footprints, or rules..."/>
                    <button type="submit" className="bg-[#1c212c] border border-[#333e54] text-[#25a5ff] hover:bg-[#232936] px-4 rounded-xl text-xs font-bold uppercase tracking-wider cursor-pointer transition">Query</button>
                  </form>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'threat_graph' && (
            <div key={activeTab} className={workspaceAnimationDirection === 'right' ? 'workspace-panel-enter' : 'workspace-panel-enter-left'}>
              <div className="bg-[#131926]/80 border border-[#25a5ff]/15 rounded-2xl p-6 space-y-4">
                <div className="flex justify-between items-center border-b border-white/5 pb-3">
                  <h3 className="text-sm font-bold uppercase tracking-wider text-[#25a5ff] flex items-center gap-2"><BarChart3 size={18}/> Real-World Daily Threat Clustering Core Feed</h3>
                  <span className="text-[10px] tracking-wider font-mono font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">Sync: Live Feed Channel</span>
                </div>
                <p className="text-xs text-[#94a3b8] font-sans">Visualizing aggregated telemetry indexes capturing wild activity spikes across primary classification sectors over the current trailing 7-day logging framework.</p>
                
                <div className="w-full h-80 pt-4 font-mono text-xs">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={threatTimelineData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                      <defs>
                        <linearGradient id="colorRansom" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ef4444" stopOpacity={0.2}/><stop offset="95%" stopColor="#ef4444" stopOpacity={0}/></linearGradient>
                        <linearGradient id="colorTrojan" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#f97316" stopOpacity={0.2}/><stop offset="95%" stopColor="#f97316" stopOpacity={0}/></linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#25a5ff" opacity={0.05} />
                      <XAxis dataKey="date" stroke="#576575" />
                      <YAxis stroke="#576575" />
                      <Tooltip contentStyle={{ backgroundColor: '#0e121a', borderColor: '#25a5ff', borderRadius: '12px', fontSize: '11px' }} />
                      <Area type="monotone" dataKey="Ransomware" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#colorRansom)" />
                      <Area type="monotone" dataKey="Trojans" stroke="#f97316" strokeWidth={2} fillOpacity={1} fill="url(#colorTrojan)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex gap-4 justify-center text-[10px] font-bold uppercase tracking-wider pt-2 border-t border-white/5">
                  <span className="flex items-center gap-1.5 text-red-400"><span className="w-2 h-2 rounded-full bg-red-400"/> Ransomware Spikes</span>
                  <span className="flex items-center gap-1.5 text-orange-400"><span className="w-2 h-2 rounded-full bg-orange-400"/> Trojan Infiltration Logs</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );

  return (
    <div className="min-h-screen bg-[#020212] text-white font-sans relative overflow-hidden">
      <style>{`
        @keyframes authCardSlide {
          0% { opacity: 0; transform: translateX(28px); }
          100% { opacity: 1; transform: translateX(0); }
        }
        @keyframes authCardSlideReverse {
          0% { opacity: 0; transform: translateX(-28px); }
          100% { opacity: 1; transform: translateX(0); }
        }
        @keyframes workspacePanelSlide {
          0% { opacity: 0; transform: translateX(24px); }
          100% { opacity: 1; transform: translateX(0); }
        }
        @keyframes workspacePanelSlideLeft {
          0% { opacity: 0; transform: translateX(-24px); }
          100% { opacity: 1; transform: translateX(0); }
        }
        .auth-card-enter { animation: authCardSlide 450ms cubic-bezier(0.22, 1, 0.36, 1) both; }
        .auth-card-enter-reverse { animation: authCardSlideReverse 450ms cubic-bezier(0.22, 1, 0.36, 1) both; }
        .workspace-panel-enter { animation: workspacePanelSlide 480ms cubic-bezier(0.22, 1, 0.36, 1) both; }
        .workspace-panel-enter-left { animation: workspacePanelSlideLeft 480ms cubic-bezier(0.22, 1, 0.36, 1) both; }
      `}</style>

      {(!isLoggedIn || transitionState !== 'dashboard') && (
        <div className={`absolute inset-0 flex items-center justify-center transition-all duration-700 z-20 ${transitionState === 'reveal' ? 'opacity-0 -translate-x-8 scale-95 pointer-events-none' : 'opacity-100 translate-x-0 scale-100'}`}>
          {renderAuthScreen()}
        </div>
      )}

      {isLoggedIn && (
        <div className={`min-h-screen transition-all duration-700 ${transitionState === 'dashboard' ? 'opacity-100 translate-x-0 scale-100' : 'opacity-100 translate-x-10 scale-100'}`}>
          {renderDashboardScreen()}
        </div>
      )}
    </div>
  );
}