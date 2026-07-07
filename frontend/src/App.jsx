import React, { useState } from 'react';
import { LayoutDashboard, Binary, Code, History, LogOut, Upload, FileText, AlertTriangle, Mail, Lock, Eye, EyeOff, Shield } from 'lucide-react';
import logoImg from './assets/logo.png';

export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [authPage, setAuthPage] = useState('login');
  const [activeTab, setActiveTab] = useState('dashboard');
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  // --- NEW STATES FOR HANDLING THE LIVE BACKEND CONNECTION ---
  const [uploading, setUploading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);

  const handleLogin = (e) => {
    e.preventDefault();
    if (email && password) setIsLoggedIn(true);
  };

  const handleSignup = (e) => {
    e.preventDefault();
    alert('Account created! Proceeding to authentication portal.');
    setAuthPage('login');
  };

  // --- FUNCTION TO SEND FILE DATA TO THE DJANGO BACKEND API ---
  const handleFileChange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setUploading(true);
    setAnalysisResult(null);

    // Prepare the multi-part data payload stream
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('http://127.0.0.1:8000/api/v1/upload/', {
        method: 'POST',
        body: formData, // JavaScript automatically sets the correct Content-Type headers for files
      });

      if (!response.ok) {
        throw new Error('Analysis engine reported a transactional failure.');
      }

      const data = await response.json();
      setAnalysisResult(data); // Inject the JSON results into our layout state
    } catch (error) {
      console.error(error);
      alert('Error connecting to Django security console matrix.');
    } finally {
      setUploading(false);
    }
  };

  // --- 1. PREMIUM GLASSMORPHIC AUTHENTICATION SCREENS ---
  if (!isLoggedIn) {
    return (
      <div className="min-h-screen bg-[#020212] flex items-center justify-center p-4 relative overflow-hidden">
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
              <button type="submit" className="w-full bg-[#1c212c] border border-[#333e54] text-white font-medium py-4 rounded-2xl text-base cursor-pointer">Log in</button>
              <p className="text-center text-xs text-[#64748b] pt-4">Didn't have an account? <button type="button" onClick={() => setAuthPage('signup')} className="text-[#25a5ff] font-medium">Sign up</button></p>
            </form>
          ) : (
            <form onSubmit={handleSignup} className="space-y-4">
              <div className="relative">
                <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575]"><Mail size={18} /></span>
                <input type="email" className="w-full bg-[#0a0d14]/60 border border-[#25a5ff]/20 rounded-2xl pl-12 pr-4 py-4 text-white text-sm focus:border-[#25a5ff] outline-none" placeholder="Enter corporate email address" required />
              </div>
              <button type="submit" className="w-full bg-[#1c212c] border border-[#333e54] text-white font-medium py-4 rounded-2xl text-base cursor-pointer">Sign up</button>
              <p className="text-center text-xs text-[#64748b] pt-4">Already authorized? <button type="button" onClick={() => setAuthPage('login')} className="text-[#25a5ff] font-medium">Log in</button></p>
            </form>
          )}
        </div>
      </div>
    );
  }

  // --- 2. MAIN COHESIVE SECURE OPERATIONS PANEL INTERFACE ---
  return (
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
            <button onClick={() => setActiveTab('dashboard')} className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl text-sm font-medium cursor-pointer ${activeTab === 'dashboard' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926]'}`}><LayoutDashboard size={18} /><span>Triage Dashboard</span></button>
            <button onClick={() => setActiveTab('pe_parser')} className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl text-sm font-medium cursor-pointer ${activeTab === 'pe_parser' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926]'}`}><Binary size={18} /><span>PE Static Parser</span></button>
            <button onClick={() => setActiveTab('yara_engine')} className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl text-sm font-medium cursor-pointer ${activeTab === 'yara_engine' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926]'}`}><Code size={18} /><span>YARA Signatures</span></button>
            <button onClick={() => setActiveTab('history')} className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl text-sm font-medium cursor-pointer ${activeTab === 'history' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926]'}`}><History size={18} /><span>Analysis Logs</span></button>
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

        {activeTab === 'dashboard' && (
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
        )}

        {activeTab !== 'dashboard' && (
          <div className="border border-[#25a5ff]/10 bg-[#131926]/30 rounded-2xl p-14 text-center text-[#576575] text-sm font-medium">
            📡 Integration state active. Awaiting JSON stream pipeline synchronization.
          </div>
        )}
      </main>
    </div>
  );
}