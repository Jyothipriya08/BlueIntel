import React, { useState, useEffect, useRef } from 'react';
import { LayoutDashboard, Binary, Code, History, LogOut, Upload, FileText, AlertTriangle, Mail, Lock, Eye, EyeOff, Shield } from 'lucide-react';
import logoImg from './assets/logo.png';

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

  // --- MONITOR REDIRECT PARAMS TO SET LOGIN STATE LINK ---
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('auth') === 'success') {
      setIsLoggedIn(true);
      // Strip out the query param clean to keep the workspace address bar neat
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
    setAuthPage('login');
  };

  const switchAuthPage = (nextPage) => {
    setAuthAnimationDirection(nextPage === 'signup' ? 'forward' : 'reverse');
    setAuthPage(nextPage);
  };

  const switchTab = (nextTab) => {
    const tabOrder = ['dashboard', 'pe_parser', 'yara_engine', 'history'];
    const currentIndex = tabOrder.indexOf(activeTab);
    const nextIndex = tabOrder.indexOf(nextTab);
    setWorkspaceAnimationDirection(nextIndex >= currentIndex ? 'right' : 'left');
    setActiveTab(nextTab);
  };

  // --- FUNCTION TO SEND FILE DATA TO THE DJANGO BACKEND API ---
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

      if (!response.ok) {
        throw new Error('Analysis engine reported a transactional failure.');
      }

      const data = await response.json();
      setAnalysisResult(data); 
    } catch (error) {
      console.error(error);
      alert('Error connecting to Django security console matrix.');
    } finally {
      setUploading(false);
    }
  };

  const renderAuthScreen = () => (
    <div className="min-h-screen bg-[#020212] flex items-center justify-center p-4 relative overflow-hidden">
      {/* Futuristic ambient background glow elements */}
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
          <div key={authPage} className={authAnimationDirection === 'forward' ? 'auth-card-enter' : 'auth-card-enter-reverse'}>
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

                {/* ACTIVE OAUTH THIRD-PARTY BUTTON GRID */}
                <div className="grid grid-cols-3 gap-3 pt-2">
                  {/* Facebook Pipeline Auth Trigger */}
                  <button 
                    type="button" 
                    onClick={() => window.location.href = 'http://127.0.0.1:8000/accounts/facebook/login/'}
                    className="bg-[#131722]/80 hover:bg-[#1a1f2e] border border-[#222b3d] text-xs py-3 rounded-xl text-[#94a3b8] hover:text-white transition cursor-pointer font-medium text-center"
                  >
                    Facebook
                  </button>
                  
                  {/* Google Pipeline Auth Trigger */}
                  <button 
                    type="button" 
                    onClick={() => window.location.href = 'http://127.0.0.1:8000/accounts/google/login/'}
                    className="bg-[#131722]/80 hover:bg-[#1a1f2e] border border-[#222b3d] text-xs py-3 rounded-xl text-white hover:border-[#25a5ff]/40 shadow-md transition cursor-pointer font-semibold text-center"
                  >
                    Google
                  </button>
                  
                  <button 
                    type="button" 
                    className="bg-[#131722]/80 hover:bg-[#1a1f2e] border border-[#222b3d] text-xs py-3 rounded-xl text-[#94a3b8] opacity-50 cursor-not-allowed font-medium text-center" 
                    disabled
                  >
                    Apple
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
    <div className="min-h-screen bg-[#020212] flex text-white font-sans relative overflow-hidden">
      {/* SIDEBAR NAVIGATION */}
      <aside className="w-64 bg-gradient-to-b from-[#0e121a] to-[#07090f] border-r border-[#25a5ff]/10 flex flex-col justify-between p-5 z-10">
        <div>
          <div className="flex items-center space-x-3 mb-10 mt-2 px-1">
            <img src={logoImg} alt="BlueIntel" className="w-9 h-9 object-contain drop-shadow-[0_0_8px_rgba(37,165,255,0.3)]" />
            <div className="flex flex-col">
              <span className="font-bold text-md tracking-wider text-white">BLUE<span className="text-[#25a5ff]">INTEL</span></span>
              <span className="text-[9px] tracking-widest uppercase text-[#576575] mt-1 font-semibold">Security Engine</span>
            </div>
          </div>

          <nav className="space-y-1.5">
            <button onClick={() => switchTab('dashboard')} className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl text-sm font-medium cursor-pointer ${activeTab === 'dashboard' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926]'}`}><LayoutDashboard size={18} /><span>Triage Dashboard</span></button>
            <button onClick={() => switchTab('pe_parser')} className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl text-sm font-medium cursor-pointer ${activeTab === 'pe_parser' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926]'}`}><Binary size={18} /><span>PE Static Parser</span></button>
            <button onClick={() => switchTab('yara_engine')} className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl text-sm font-medium cursor-pointer ${activeTab === 'yara_engine' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926]'}`}><Code size={18} /><span>YARA Signatures</span></button>
            <button onClick={() => switchTab('history')} className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl text-sm font-medium cursor-pointer ${activeTab === 'history' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926]'}`}><History size={18} /><span>Analysis Logs</span></button>
          </nav>
        </div>

        <div className="border-t border-[#25a5ff]/10 pt-4 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-full bg-[#25a5ff]/10 text-[#25a5ff] flex items-center justify-center text-xs font-bold border border-[#25a5ff]/20">OP</div>
            <div className="text-left">
              <p className="text-xs font-bold text-white truncate max-w-[110px]">Operator-01</p>
              <p className="text-[10px] text-[#576575] uppercase font-semibold">Level 3 SecOps</p>
            </div>
          </div>
          <button onClick={() => setIsLoggedIn(false)} className="text-[#94a3b8] hover:text-red-400 p-2 rounded-xl hover:bg-red-500/10"><LogOut size={16} /></button>
        </div>
      </aside>

      {/* MAIN WORKSPACE AREA */}
      <main className="flex-1 p-8 overflow-y-auto z-10 relative">
        <header className="mb-8 flex justify-between items-center">
          <div>
            <h2 className="text-3xl font-semibold tracking-tight text-white capitalize">{activeTab.replace('_', ' ')} Core</h2>
            <p className="text-sm text-[#94a3b8] mt-1">Operational console node synchronized to active local static & signature scanners.</p>
          </div>
          <div className="bg-[#131926]/80 border border-[#25a5ff]/20 text-xs px-4 py-2 rounded-xl text-[#25a5ff] font-mono font-bold uppercase tracking-wider">
            ● System Matrix: Active
          </div>
        </header>

        <div className="relative overflow-hidden">
          {activeTab === 'dashboard' && (
            <div key={activeTab} className={workspaceAnimationDirection === 'right' ? 'workspace-panel-enter' : 'workspace-panel-enter-left'}>
              <div className="space-y-6">
                {/* INTERACTIVE UPLOADER CONNECTED TO FORM INPUT */}
                <label className="border border-dashed border-[#25a5ff]/30 bg-gradient-to-b from-[#131926]/40 to-[#0e121a]/40 hover:from-[#131926]/60 hover:to-[#0e121a]/60 hover:border-[#25a5ff]/70 transition-all rounded-2xl p-14 text-center flex flex-col items-center justify-center cursor-pointer group shadow-lg block">
                  <input type="file" onChange={handleFileChange} className="hidden" disabled={uploading} />
                  <div className="w-14 h-14 rounded-full bg-[#25a5ff]/5 text-[#25a5ff] flex items-center justify-center mb-4 border border-[#25a5ff]/20 group-hover:scale-105 transition-all">
                    <Upload size={24} />
                  </div>
                  <h3 className="text-lg font-medium text-white mb-1">
                    {uploading ? 'Processing Core Analysis Engine...' : 'Ingest Malicious Threat Payload'}
                  </h3>
                  <p className="text-xs text-[#94a3b8] max-w-sm mb-5">
                    {uploading ? 'Calculating hashes, parsing PE blocks, and running YARA signature matrix scanning...' : 'Upload executable PE files, text scripts, or system documentation for signature mapping.'}
                  </p>
                  {!uploading && (
                    <span className="bg-[#1c212c] border border-[#333e54] text-[#25a5ff] font-medium px-5 py-2.5 rounded-xl text-xs tracking-wide shadow-md pointer-events-none">
                      Browse Files
                    </span>
                  )}
                </label>

                {/* REAL-TIME PARSED RESULTS WORKSPACE PANEL */}
                {analysisResult && (
                  <div className="bg-[#131926]/90 border border-[#25a5ff]/15 rounded-2xl p-6 space-y-6 shadow-2xl transition-all animate-fadeIn">
                    <h3 className="text-xl font-semibold border-b border-[#25a5ff]/10 pb-3 text-white flex items-center gap-2">
                      <Shield size={20} className="text-[#25a5ff]" /> Static Analysis Intelligence Output
                    </h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div className="bg-[#020212]/50 p-4 rounded-xl border border-[#25a5ff]/5">
                        <p className="text-[#576575] font-semibold uppercase text-[11px] tracking-wider">Target Filename</p>
                        <p className="font-mono text-white mt-1 break-all">{analysisResult.file_name}</p>
                      </div>
                      <div className="bg-[#020212]/50 p-4 rounded-xl border border-[#25a5ff]/5">
                        <p className="text-[#576575] font-semibold uppercase text-[11px] tracking-wider">File Size</p>
                        <p className="font-mono text-white mt-1">{analysisResult.file_size_bytes.toLocaleString()} Bytes</p>
                      </div>
                      <div className="bg-[#020212]/50 p-4 rounded-xl border border-[#25a5ff]/5 md:col-span-2">
                        <p className="text-[#576575] font-semibold uppercase text-[11px] tracking-wider">SHA-256 Fingerprint</p>
                        <p className="font-mono text-[#25a5ff] mt-1 break-all">{analysisResult.sha256}</p>
                      </div>
                      <div className="bg-[#020212]/50 p-4 rounded-xl border border-[#25a5ff]/5">
                        <p className="text-[#576575] font-semibold uppercase text-[11px] tracking-wider">Shannon Information Entropy</p>
                        <p className={`font-mono mt-1 text-lg font-bold ${analysisResult.entropy > 7.0 ? 'text-orange-400' : 'text-emerald-400'}`}>
                          {analysisResult.entropy} {analysisResult.entropy > 7.0 && <span className="text-xs font-sans font-medium px-2 py-0.5 bg-orange-500/10 rounded border border-orange-500/20 ml-2">⚠️ Packed/Obfuscated Potential</span>}
                        </p>
                      </div>
                      <div className="bg-[#020212]/50 p-4 rounded-xl border border-[#25a5ff]/5">
                        <p className="text-[#576575] font-semibold uppercase text-[11px] tracking-wider">Windows PE Binary Binary Structure</p>
                        <p className="font-mono mt-1 font-semibold">{analysisResult.is_pe ? '🟢 Valid Executable Identifier Map' : '⚪ Generic Non-Binary Asset Log'}</p>
                      </div>
                      {/* --- NEW FEATURE UI: LIVE MALWARE VERDICT ALERT CARD --- */}
{analysisResult.malware_classification && (
  <div className={`md:col-span-2 p-5 rounded-2xl border ${
    analysisResult.malware_classification.verdict === 'MALICIOUS' 
      ? 'bg-red-500/10 border-red-500/30 text-red-400' 
      : analysisResult.malware_classification.verdict === 'SUSPICIOUS'
      ? 'bg-orange-500/10 border-orange-500/30 text-orange-400'
      : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
  }`}>
    <div className="flex justify-between items-center mb-2">
      <span className="font-bold tracking-wide uppercase text-xs">⚠️ Core Engine Threat Verdict</span>
      <span className="font-mono font-bold text-lg px-3 py-1 rounded-xl bg-black/40">
        {analysisResult.malware_classification.verdict} ({analysisResult.malware_classification.score}/100)
      </span>
    </div>
    <ul className="text-xs list-disc list-inside space-y-1 text-[#94a3b8] mt-2">
      {analysisResult.malware_classification.indicators.map((ind, i) => (
        <li key={i} className="font-sans">{ind}</li>
      ))}
      {analysisResult.malware_classification.indicators.length === 0 && (
        <li className="font-sans text-emerald-400">File exhibits baseline behavioral metrics. No anomalies flagged.</li>
      )}
    </ul>
  </div>
)}

{/* --- NEW FEATURE UI: AUTOMATED IOC TRACKING ARRAYS --- */}
{analysisResult.iocs && (
  <div className="md:col-span-2 grid grid-cols-1 md:grid-cols-3 gap-4 border-t border-[#25a5ff]/10 pt-4">
    <div className="bg-[#020212]/40 p-4 rounded-xl border border-[#25a5ff]/5">
      <p className="text-[#576575] font-semibold uppercase text-[11px] tracking-wider mb-2">Network IPs Identified</p>
      {analysisResult.iocs.ips.length > 0 ? (
        <div className="space-y-1">{analysisResult.iocs.ips.map((ip, i) => <p key={i} className="font-mono text-xs text-orange-400 bg-orange-500/5 px-2 py-1 rounded border border-orange-500/10">{ip}</p>)}</div>
      ) : <p className="text-xs text-[#576575] italic">None extracted</p>}
    </div>
    <div className="bg-[#020212]/40 p-4 rounded-xl border border-[#25a5ff]/5">
      <p className="text-[#576575] font-semibold uppercase text-[11px] tracking-wider mb-2">C2 Domains Logged</p>
      {analysisResult.iocs.domains.length > 0 ? (
        <div className="space-y-1">{analysisResult.iocs.domains.map((dom, i) => <p key={i} className="font-mono text-xs text-orange-400 bg-orange-500/5 px-2 py-1 rounded border border-orange-500/10 break-all">{dom}</p>)}</div>
      ) : <p className="text-xs text-[#576575] italic">None extracted</p>}
    </div>
    <div className="bg-[#020212]/40 p-4 rounded-xl border border-[#25a5ff]/5">
      <p className="text-[#576575] font-semibold uppercase text-[11px] tracking-wider mb-2">Registry Persistences</p>
      {analysisResult.iocs.registry_keys.length > 0 ? (
        <div className="space-y-1">{analysisResult.iocs.registry_keys.map((reg, i) => <p key={i} className="font-mono text-[10px] text-orange-400 bg-orange-500/5 px-2 py-1 rounded border border-orange-500/10 break-all">{reg}</p>)}</div>
      ) : <p className="text-xs text-[#576575] italic">None extracted</p>}
    </div>
  </div>
)}
                    </div>

                    {/* YARA SIGNATURE TRIGGER MATCHES LIST */}
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
                        <p className="text-emerald-400 font-mono text-sm font-semibold">🟢 No malicious string signatures detected in scanning grid arrays.</p>
                      )}
                    </div>
                  </div>
                )}

                {/* STATIC DASHBOARD BASELINE VISUAL COUNTERS */}
                {!analysisResult && (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-gradient-to-br from-[#131926]/80 to-[#0e121a]/80 border border-[#25a5ff]/10 rounded-2xl p-6 flex items-center space-x-4 shadow-md">
                      <div className="p-3 bg-[#25a5ff]/10 text-[#25a5ff] rounded-xl border border-[#25a5ff]/10"><FileText size={20} /></div>
                      <div><h4 className="text-3xl font-bold font-mono text-white">1,402</h4><p className="text-[11px] text-[#576575] font-semibold uppercase tracking-wider mt-0.5">Scans Run Successfully</p></div>
                    </div>
                    <div className="bg-gradient-to-br from-[#131926]/80 to-[#0e121a]/80 border border-[#25a5ff]/10 rounded-2xl p-6 flex items-center space-x-4 shadow-md">
                      <div className="p-3 bg-[#ef4444]/10 text-red-400 rounded-xl border border-red-500/10"><AlertTriangle size={20} /></div>
                      <div><h4 className="text-3xl font-bold font-mono text-red-400">84</h4><p className="text-[11px] text-[#576575] font-semibold uppercase tracking-wider mt-0.5">High Risk Signature Matches</p></div>
                    </div>
                    <div className="bg-gradient-to-br from-[#131926]/80 to-[#0e121a]/80 border border-[#25a5ff]/10 rounded-2xl p-6 flex items-center space-x-4 shadow-md">
                      <div className="p-3 bg-emerald-500/10 text-emerald-400 rounded-xl border border-emerald-500/10"><FileText size={20} /></div>
                      <div><h4 className="text-3xl font-bold font-mono text-emerald-400">94.01%</h4><p className="text-[11px] text-[#576575] font-semibold uppercase tracking-wider mt-0.5">Local Engine Detection Score</p></div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab !== 'dashboard' && (
            <div key={activeTab} className={workspaceAnimationDirection === 'right' ? 'workspace-panel-enter' : 'workspace-panel-enter-left'}>
              <div className="border border-[#25a5ff]/10 bg-[#131926]/30 rounded-2xl p-14 text-center text-[#576575] text-sm font-medium">
                📡 Integration state active. Awaiting JSON stream pipeline synchronization.
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