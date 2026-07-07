import React, { useState } from 'react';
import { LayoutDashboard, Binary, Code, History, LogOut, Upload, FileText, AlertTriangle, Mail, Lock, Eye, EyeOff, Shield } from 'lucide-react';

export default function App() {
  // Navigation & Authentication states
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [authPage, setAuthPage] = useState('login'); // 'login' or 'signup'
  const [activeTab, setActiveTab] = useState('dashboard');
  
  // UI interaction states
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleLogin = (e) => {
    e.preventDefault();
    if (email && password) setIsLoggedIn(true);
  };

  const handleSignup = (e) => {
    e.preventDefault();
    alert('Account created! Proceeding to authentication portal.');
    setAuthPage('login');
  };

  // --- 1. PREMIUM GLASSMORPHIC AUTHENTICATION SCREENS ---
  if (!isLoggedIn) {
    return (
      <div className="min-h-screen bg-[#020212] flex items-center justify-center p-4 relative overflow-hidden">
        {/* Futuristic background glow elements mirroring the design reference */}
        <div className="absolute top-1/2 left-1/4 -translate-y-1/2 w-[500px] h-[500px] bg-[#25a5ff]/10 rounded-full blur-[120px] pointer-events-none" />
        <div className="absolute top-1/2 right-1/4 -translate-y-1/2 w-[500px] h-[500px] bg-[#25a5ff]/5 rounded-full blur-[140px] pointer-events-none" />

        {/* The Card Container: Features a smooth dark gradient, translucent backdrop blur, and subtle outer blue ambient glow */}
        <div className="backdrop-blur-md bg-gradient-to-b from-[#181d28]/90 to-[#0e121a]/90 p-10 rounded-3xl border border-[#25a5ff]/15 w-full max-w-lg shadow-[0_0_50px_rgba(37,165,255,0.06)] transition-all">
          
          <div className="text-center mb-8">
            <h1 className="text-4xl font-semibold tracking-tight text-white mb-3">
              {authPage === 'login' ? 'Log in' : 'Sign up'}
            </h1>
            <p className="text-sm text-[#94a3b8] leading-relaxed max-w-sm mx-auto">
              {authPage === 'login' 
                ? 'Log in to your account and seamlessly continue managing your projects, ideas, and progress just where you left off.'
                : 'Create an analyst account to configure local malware rule matrices and establish active security ingestion pipelines.'
              }
            </p>
          </div>

          {authPage === 'login' ? (
            /* --- LOGIN MATRIX --- */
            <form onSubmit={handleLogin} className="space-y-4">
              {/* Email Input Field */}
              <div className="relative">
                <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575]">
                  <Mail size={18} />
                </span>
                <input 
                  type="email" 
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-[#0a0d14]/60 border border-[#25a5ff]/20 rounded-2xl pl-12 pr-4 py-4 text-white text-sm placeholder-[#576575] focus:border-[#25a5ff] focus:ring-1 focus:ring-[#25a5ff] outline-none transition"
                  placeholder="Enter your email address"
                  required
                />
              </div>

              {/* Password Input Field with Visibility Toggle Toggle */}
              <div className="relative">
                <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575]">
                  <Lock size={18} />
                </span>
                <input 
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-[#0a0d14]/60 border border-[#25a5ff]/20 rounded-2xl pl-12 pr-12 py-4 text-white text-sm placeholder-[#576575] focus:border-[#25a5ff] focus:ring-1 focus:ring-[#25a5ff] outline-none transition"
                  placeholder="Enter your password"
                  required
                />
                <button 
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-[#576575] hover:text-[#25a5ff] transition cursor-pointer"
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>

              {/* Primary Submission Action */}
              <button 
                type="submit" 
                className="w-full bg-[#1c212c] hover:bg-[#232936] border border-[#333e54] text-white font-medium py-4 rounded-2xl text-base tracking-wide transition shadow-md cursor-pointer mt-2"
              >
                Log in
              </button>

              {/* OAUTH SSO Buttons */}
              <div className="grid grid-cols-3 gap-3 pt-2">
                <button type="button" className="bg-[#131722]/80 hover:bg-[#1a1f2e] border border-[#222b3d] text-xs py-3 rounded-xl text-[#94a3b8] transition cursor-pointer font-medium">Facebook</button>
                <button type="button" className="bg-[#131722]/80 hover:bg-[#1a1f2e] border border-[#222b3d] text-xs py-3 rounded-xl text-[#94a3b8] transition cursor-pointer font-medium">Google</button>
                <button type="button" className="bg-[#131722]/80 hover:bg-[#1a1f2e] border border-[#222b3d] text-xs py-3 rounded-xl text-[#94a3b8] transition cursor-pointer font-medium">Apple</button>
              </div>

              <p className="text-center text-xs text-[#64748b] pt-4">
                Didn't have an account?{' '}
                <button type="button" onClick={() => setAuthPage('signup')} className="text-[#25a5ff] hover:underline cursor-pointer font-medium">
                  Sign up
                </button>
              </p>
            </form>
          ) : (
            /* --- SIGNUP MATRIX --- */
            <form onSubmit={handleSignup} className="space-y-4">
              <div className="relative">
                <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575]"><Mail size={18} /></span>
                <input 
                  type="email" 
                  className="w-full bg-[#0a0d14]/60 border border-[#25a5ff]/20 rounded-2xl pl-12 pr-4 py-4 text-white text-sm placeholder-[#576575] focus:border-[#25a5ff] focus:ring-1 focus:ring-[#25a5ff] outline-none transition"
                  placeholder="Enter corporate email address"
                  required
                />
              </div>
              <div className="relative">
                <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575]"><Lock size={18} /></span>
                <input 
                  type="password" 
                  className="w-full bg-[#0a0d14]/60 border border-[#25a5ff]/20 rounded-2xl pl-12 pr-4 py-4 text-white text-sm placeholder-[#576575] focus:border-[#25a5ff] focus:ring-1 focus:ring-[#25a5ff] outline-none transition"
                  placeholder="Create operational access password"
                  required
                />
              </div>
              
              <button 
                type="submit" 
                className="w-full bg-[#1c212c] hover:bg-[#232936] border border-[#333e54] text-white font-medium py-4 rounded-2xl text-base tracking-wide transition shadow-md cursor-pointer mt-2"
              >
                Sign up
              </button>

              <p className="text-center text-xs text-[#64748b] pt-4">
                Already authorized?{' '}
                <button type="button" onClick={() => setAuthPage('login')} className="text-[#25a5ff] hover:underline cursor-pointer font-medium">
                  Log in
                </button>
              </p>
            </form>
          )}
        </div>
      </div>
    );
  }

  // --- 2. MAIN COHESIVE SECURE OPERATIONS PANEL INTERFACE ---
  return (
    <div className="min-h-screen bg-[#020212] flex text-white font-sans relative overflow-hidden">
      
      {/* PERSISTENT LEFT SIDEBAR PANEL */}
      <aside className="w-64 bg-gradient-to-b from-[#0e121a] to-[#07090f] border-r border-[#25a5ff]/10 flex flex-col justify-between p-5 z-10">
        <div>
          {/* Custom Brand Identity Alignment - Embedded in Top Left Corner */}
          <div className="flex items-center space-x-3 mb-10 mt-2 px-1">
            <div className="w-9 h-9 bg-[#020212] border-2 border-[#25a5ff] rounded-xl flex items-center justify-center text-[#25a5ff] font-bold text-lg shadow-[0_0_15px_rgba(37,165,255,0.25)]">
              B
            </div>
            <div className="flex flex-col">
              <span className="font-bold text-md tracking-wider leading-none text-white">BLUE<span className="text-[#25a5ff]">INTEL</span></span>
              <span className="text-[9px] tracking-widest uppercase text-[#576575] mt-1 font-semibold">Security Engine</span>
            </div>
          </div>

          {/* Feature Navigation Stack matching theme colors */}
          <nav className="space-y-1.5">
            <button 
              onClick={() => setActiveTab('dashboard')}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl text-sm transition font-medium cursor-pointer ${activeTab === 'dashboard' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926] hover:text-white'}`}
            >
              <LayoutDashboard size={18} />
              <span>Triage Dashboard</span>
            </button>
            <button 
              onClick={() => setActiveTab('pe_parser')}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl text-sm transition font-medium cursor-pointer ${activeTab === 'pe_parser' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926] hover:text-white'}`}
            >
              <Binary size={18} />
              <span>PE Static Parser</span>
            </button>
            <button 
              onClick={() => setActiveTab('yara_engine')}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl text-sm transition font-medium cursor-pointer ${activeTab === 'yara_engine' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926] hover:text-white'}`}
            >
              <Code size={18} />
              <span>YARA Signatures</span>
            </button>
            <button 
              onClick={() => setActiveTab('history')}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl text-sm transition font-medium cursor-pointer ${activeTab === 'history' ? 'bg-[#25a5ff]/10 text-[#25a5ff] border border-[#25a5ff]/20' : 'text-[#94a3b8] hover:bg-[#131926] hover:text-white'}`}
            >
              <History size={18} />
              <span>Analysis Logs</span>
            </button>
          </nav>
        </div>

        {/* Analyst Session Controls */}
        <div className="border-t border-[#25a5ff]/10 pt-4 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-full bg-[#25a5ff]/10 text-[#25a5ff] flex items-center justify-center text-xs font-bold border border-[#25a5ff]/20">
              OP
            </div>
            <div className="text-left">
              <p className="text-xs font-bold text-white truncate max-w-[110px]">Operator-01</p>
              <p className="text-[10px] text-[#576575] uppercase tracking-wider font-semibold">Level 3 SecOps</p>
            </div>
          </div>
          <button 
            onClick={() => setIsLoggedIn(false)}
            className="text-[#94a3b8] hover:text-red-400 p-2 rounded-xl hover:bg-red-500/10 transition cursor-pointer"
            title="Terminate Link"
          >
            <LogOut size={16} />
          </button>
        </div>
      </aside>

      {/* DYNAMIC WORKSPACE PANE */}
      <main className="flex-1 p-8 overflow-y-auto z-10 relative">
        <header className="mb-8 flex justify-between items-center">
          <div>
            <h2 className="text-3xl font-semibold tracking-tight text-white capitalize">{activeTab.replace('_', ' ')} Core</h2>
            <p className="text-sm text-[#94a3b8] mt-1">Operational console node synchronized to active local static & signature scanners.</p>
          </div>
          <div className="bg-[#131926]/80 border border-[#25a5ff]/20 text-xs px-4 py-2 rounded-xl text-[#25a5ff] font-mono font-bold uppercase tracking-wider shadow-[0_0_15px_rgba(37,165,255,0.04)]">
            ● System Matrix: Active
          </div>
        </header>

        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* INGEST UPLOADER ZONE */}
            <div className="border border-dashed border-[#25a5ff]/30 bg-gradient-to-b from-[#131926]/40 to-[#0e121a]/40 hover:from-[#131926]/60 hover:to-[#0e121a]/60 hover:border-[#25a5ff]/70 transition-all rounded-2xl p-14 text-center flex flex-col items-center justify-center cursor-pointer group shadow-lg">
              <div className="w-14 h-14 rounded-full bg-[#25a5ff]/5 text-[#25a5ff] flex items-center justify-center mb-4 border border-[#25a5ff]/20 group-hover:scale-105 transition-all shadow-[0_0_20px_rgba(37,165,255,0.05)]">
                <Upload size={24} />
              </div>
              <h3 className="text-lg font-medium text-white mb-1">Ingest Malicious Threat Payload</h3>
              <p className="text-xs text-[#94a3b8] max-w-sm mb-5">Upload executable PE files, text scripts, or system documentation for signature mapping.</p>
              <button className="bg-[#1c212c] hover:bg-[#232936] border border-[#333e54] text-[#25a5ff] font-medium px-5 py-2.5 rounded-xl text-xs transition tracking-wide shadow-md">
                Browse Files
              </button>
            </div>

            {/* LIVE CONSOLE COUNTERS */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-gradient-to-br from-[#131926]/80 to-[#0e121a]/80 border border-[#25a5ff]/10 rounded-2xl p-6 flex items-center space-x-4 shadow-md">
                <div className="p-3 bg.5 bg-[#25a5ff]/10 text-[#25a5ff] rounded-xl border border-[#25a5ff]/10"><FileText size={20} /></div>
                <div>
                  <h4 className="text-3xl font-bold font-mono text-white">1,402</h4>
                  <p className="text-[11px] text-[#576575] font-semibold uppercase tracking-wider mt-0.5">Scans Run Successfully</p>
                </div>
              </div>
              <div className="bg-gradient-to-br from-[#131926]/80 to-[#0e121a]/80 border border-[#25a5ff]/10 rounded-2xl p-6 flex items-center space-x-4 shadow-md">
                <div className="p-3 bg-[#ef4444]/10 text-red-400 rounded-xl border border-red-500/10"><AlertTriangle size={20} /></div>
                <div>
                  <h4 className="text-3xl font-bold font-mono text-red-400">84</h4>
                  <p className="text-[11px] text-[#576575] font-semibold uppercase tracking-wider mt-0.5">High Risk Signature Matches</p>
                </div>
              </div>
              <div className="bg-gradient-to-br from-[#131926]/80 to-[#0e121a]/80 border border-[#25a5ff]/10 rounded-2xl p-6 flex items-center space-x-4 shadow-md">
                <div className="p-3 bg-emerald-500/10 text-emerald-400 rounded-xl border border-emerald-500/10"><Shield size={20} /></div>
                <div>
                  <h4 className="text-3xl font-bold font-mono text-emerald-400">94.01%</h4>
                  <p className="text-[11px] text-[#576575] font-semibold uppercase tracking-wider mt-0.5">Local Engine Detection Score</p>
                </div>
              </div>
            </div>
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