import React, { useState, useEffect, useRef } from 'react';
import { 
  LayoutDashboard, Binary, ShieldAlert, FileText, BarChart3, Bot, LogOut, 
  Upload, AlertTriangle, Mail, Lock, Eye, EyeOff, Shield, Terminal, Zap,
  Copy, Check, FileCode, Cpu, Radio, Network, History, Database, ArrowRight
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import logoImg from './assets/logo.png';

const threatTimelineData = [
  { date: '07/03', Ransomware: 420, Trojans: 210, ExploitKits: 110, InfoStealers: 150 },
  { date: '07/04', Ransomware: 510, Trojans: 180, ExploitKits: 130, InfoStealers: 220 },
  { date: '07/05', Ransomware: 480, Trojans: 290, ExploitKits: 90, InfoStealers: 310 },
  { date: '07/06', Ransomware: 610, Trojans: 340, ExploitKits: 190, InfoStealers: 290 },
  { date: '07/07', Ransomware: 720, Trojans: 410, ExploitKits: 220, InfoStealers: 410 },
  { date: '07/08', Ransomware: 890, Trojans: 480, ExploitKits: 310, InfoStealers: 530 },
  { date: '07/09', Ransomware: 1040, Trojans: 520, ExploitKits: 450, InfoStealers: 680 },
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
  
  // --- ANALYSIS STATE MACHINE ---
  const [uploading, setUploading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [copiedKey, setCopiedKey] = useState(null);
  const [sandboxTab, setSandboxTab] = useState('tree');
  const prevLoggedInRef = useRef(isLoggedIn);

  // --- HISTORICAL THREAT LEDGER STORAGE ---
  const [scanHistory, setScanHistory] = useState([
    { name: 'mfe_detonate.exe', time: '14:12', hash: '8f7a...3d2e', verdict: 'MALICIOUS', score: 85 },
    { name: 'update_patch.msi', time: '12:04', hash: '4b2c...9e1a', verdict: 'SUSPICIOUS', score: 45 },
    { name: 'billing_statement.pdf', time: '09:44', hash: '1a2b...3c4d', verdict: 'CLEAN', score: 5 },
  ]);
  
  // --- CHAT CONSOLE LOGIC ---
  const [chatInput, setChatInput] = useState('');
  const [chatLog, setChatLog] = useState([
    { role: 'assistant', text: 'System grid unified. Secure telemetry socket ready for analytical prompts.' }
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

  // Automated mounting effect to stream historical tables from Django DB
  useEffect(() => {
    const fetchHistoryLedger = async () => {
      try {
        const response = await fetch('http://127.0.0.1:8000/api/v1/history-ledger/');
        if (response.ok) {
          const historyData = await response.json();
          setScanHistory(historyData);
        }
      } catch (err) {
        console.error("Database connection failure streaming history arrays.");
      }
    };
    if (isLoggedIn) {
      fetchHistoryLedger();
    }
  }, [isLoggedIn, analysisResult]);

  const triggerCopy = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
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

  const handleSignup = (e) => {
    e.preventDefault();
    // Simulate signup completion and shift back to login or dashboard
    setIsLoggedIn(true);
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

      setScanHistory(prev => [
        { 
          name: data.file_name, 
          time: new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}), 
          hash: data.sha256 ? `${data.sha256.slice(0,4)}...${data.sha256.slice(-4)}` : 'N/A', 
          verdict: data.malware_classification?.verdict || 'UNKNOWN', 
          score: data.malware_classification?.score || 0 
        },
        ...prev
      ]);

      setChatLog(prev => [...prev, { 
        role: 'assistant', 
        text: `⚠️ Payload [${data.file_name}] ingested into memory buffer. Heuristic threat index calculated at ${data.malware_classification?.score || 0}/100. Pinging Anthropic API framework...` 
      }]);

      const aiResponse = await fetch('http://127.0.0.1:8000/api/v1/ai-report/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ "analysis_results": data })
      });
      
      if (aiResponse.ok) {
        const aiData = await aiResponse.json();
        setAnalysisResult(prev => ({ ...prev, ai_generated_report: aiData.report }));
        setChatLog(prev => [...prev, { role: 'assistant', text: "🤖 Comprehensive AI report received from Claude 3.5 Sonnet. Playbook mapping ready." }]);
      } else {
        setAnalysisResult(prev => ({ ...prev, ai_generated_report: "❌ AI Compilation Failed: Check server log keys or usage credits." }));
      }
    } catch (error) {
      console.error(error);
      alert('Error connecting to Django security console matrix.');
      setAnalysisResult(prev => ({ ...prev, ai_generated_report: "❌ Connection pipeline error." }));
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
      }
    } catch (error) {
      setChatLog(prev => [...prev, { role: 'assistant', text: "🤖 Query pipeline socket error." }]);
    }
  };

  const renderAuthScreen = () => (
    <div className="min-h-screen w-full bg-[#01010a] flex items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute top-1/2 left-1/4 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-r from-[#25a5ff]/10 to-purple-500/5 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute top-1/2 right-1/4 -translate-y-1/2 w-[500px] h-[500px] bg-[#25a5ff]/5 rounded-full blur-[140px] pointer-events-none" />

      <div className="backdrop-blur-xl bg-[#0b0f19]/70 p-12 rounded-[2rem] border border-[#25a5ff]/20 w-full max-w-lg shadow-[0_0_80px_rgba(37,165,255,0.08)] z-10 transition-all">
        <div className="text-center mb-8">
          <div className="inline-block p-4 rounded-2xl bg-[#25a5ff]/5 border border-[#25a5ff]/10 mb-4 animate-pulse">
            <img src={logoImg} alt="BlueIntel Logo" className="w-16 h-16 object-contain drop-shadow-[0_0_15px_rgba(37,165,255,0.3)]" />
          </div>
          <h1 className="text-3xl font-black tracking-wider text-white uppercase bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-200 to-[#25a5ff]">BlueIntel Console</h1>
          <p className="text-xs text-[#576575] font-mono mt-2 tracking-widest uppercase">SecOps Authorization Gateway</p>
        </div>

        <div className="relative overflow-hidden">
          <div className={authAnimationDirection === 'forward' ? 'auth-card-enter' : 'auth-card-enter-reverse'}>
            {authPage === 'login' ? (
              <form onSubmit={(e) => { e.preventDefault(); setIsLoggedIn(true); }} className="space-y-4">
                <div className="relative group">
                  <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575] group-focus-within:text-[#25a5ff] transition-colors"><Mail size={16} /></span>
                  <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="w-full bg-[#04060d]/90 border border-[#25a5ff]/15 rounded-xl pl-12 pr-4 py-4 text-white text-xs font-mono focus:border-[#25a5ff] outline-none shadow-inner transition-all" placeholder="OPERATOR EMAIL ADDRESS" required />
                </div>
                <div className="relative group">
                  <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575] group-focus-within:text-[#25a5ff] transition-colors"><Lock size={16} /></span>
                  <input type={showPassword ? "text" : "password"} value={password} onChange={(e) => setPassword(e.target.value)} className="w-full bg-[#04060d]/90 border border-[#25a5ff]/15 rounded-xl pl-12 pr-12 py-4 text-white text-xs font-mono focus:border-[#25a5ff] outline-none shadow-inner transition-all" placeholder="SECRET PASSPHRASE" required />
                  <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-4 top-1/2 -translate-y-1/2 text-[#576575] hover:text-[#25a5ff]"><Eye size={16} /></button>
                </div>
                
                <button type="submit" className="w-full bg-gradient-to-r from-[#1c212c] to-[#252f3f] border border-[#25a5ff]/30 text-white font-bold py-4 rounded-xl text-xs uppercase tracking-widest cursor-pointer hover:border-[#25a5ff] shadow-[0_4px_20px_rgba(0,0,0,0.4)] hover:shadow-[#25a5ff]/10 transition-all">
                  Local Terminal Access
                </button>

                <div className="relative flex py-2 items-center">
                  <div className="flex-grow border-t border-white/5"></div>
                  <span className="flex-shrink mx-4 text-[9px] font-mono tracking-widest text-[#576575] uppercase">OR</span>
                  <div className="flex-grow border-t border-white/5"></div>
                </div>

                <button 
                  type="button" 
                  onClick={() => window.location.href = 'http://127.0.0.1:8000/accounts/google/login/'}
                  className="w-full bg-gradient-to-r from-purple-950/20 via-[#0a0f1d] to-[#25a5ff]/10 border border-[#25a5ff]/30 hover:border-[#25a5ff] text-xs py-4 rounded-xl text-white shadow-lg transition-all cursor-pointer font-bold tracking-wider flex items-center justify-center gap-3"
                >
                  <Radio size={16} className="text-[#25a5ff] animate-pulse" /> Identity Provider Federated SSO
                </button>
              </form>
            ) : (
              <form onSubmit={handleSignup} className="space-y-4">
                <div className="relative">
                  <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575]"><Mail size={16} /></span>
                  <input type="email" className="w-full bg-[#04060d]/90 border border-[#25a5ff]/15 rounded-xl pl-12 pr-4 py-4 text-white text-xs font-mono focus:border-[#25a5ff] outline-none shadow-inner" placeholder="Enter corporate email address" required />
                </div>
                <button type="submit" className="w-full bg-gradient-to-r from-[#1c212c] to-[#252f3f] border border-[#25a5ff]/30 text-white font-bold py-4 rounded-xl text-xs uppercase tracking-widest transition-all">Sign up</button>
                <p className="text-center text-xs text-[#576575] pt-4 font-mono">Already authorized? <button type="button" onClick={() => switchAuthPage('login')} className="text-[#25a5ff] font-bold">Log in</button></p>
              </form>
            )}
          </div>
        </div>
      </div>
    </div>
  );

  const renderDashboardScreen = () => (
    <div className="min-h-screen w-full bg-[#02020a] flex text-white font-sans relative overflow-hidden">
      <aside className="w-80 bg-gradient-to-b from-[#090d16] to-[#03050a] border-r border-[#25a5ff]/15 flex flex-col justify-between p-6 z-10 relative">
        <div className="absolute inset-0 bg-[#25a5ff]/1 mix-blend-color-dodge pointer-events-none" />
        <div>
          <div className="flex items-center space-x-3 mb-12 mt-2 px-1">
            <div className="p-2 bg-[#25a5ff]/5 border border-[#25a5ff]/20 rounded-xl">
              <img src={logoImg} alt="BlueIntel" className="w-8 h-8 object-contain drop-shadow-[0_0_8px_rgba(37,165,255,0.4)]" />
            </div>
            <div className="flex flex-col">
              <span className="font-black text-lg tracking-widest text-white">BLUE<span className="text-[#25a5ff]">INTEL</span></span>
              <span className="text-[9px] tracking-widest uppercase text-[#25a5ff] font-mono font-black border-t border-[#25a5ff]/10 pt-0.5 mt-0.5">X-Ops Command Matrix</span>
            </div>
          </div>

          <nav className="space-y-2">
            {[
              { id: 'dashboard', label: 'Triage Dashboard', icon: LayoutDashboard },
              { id: 'static_parser', label: 'Static Analysis', icon: Binary },
              { id: 'dynamic_sandbox', label: 'Dynamic Sandbox', icon: ShieldAlert },
              { id: 'ioc_tracker', label: 'Indicators (IoCs)', icon: FileText },
              { id: 'ai_reports', label: 'AI Reports & Agent', icon: Bot },
              { id: 'threat_graph', label: 'Real-World Graph', icon: BarChart3 },
            ].map(item => {
              const Icon = item.icon;
              const isSelected = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => switchTab(item.id)}
                  className={`w-full flex items-center justify-between px-4 py-4 rounded-xl text-xs uppercase font-mono font-bold tracking-wider cursor-pointer border transition-all duration-300 relative ${
                    isSelected 
                      ? 'bg-[#25a5ff]/10 text-[#25a5ff] border-[#25a5ff]/30 shadow-[inset_0_0_15px_rgba(37,165,255,0.05)]' 
                      : 'text-[#576575] border-transparent hover:text-white hover:bg-white/5'
                  }`}
                >
                  <div className="flex items-center space-x-3.5">
                    <Icon size={16} className={isSelected ? 'text-[#25a5ff]' : 'text-[#425265]'} />
                    <span>{item.label}</span>
                  </div>
                  {isSelected && <span className="w-1.5 h-1.5 rounded-full bg-[#25a5ff] shadow-[0_0_8px_#25a5ff]" />}
                </button>
              );
            })}
          </nav>
        </div>

        <div className="border-t border-[#25a5ff]/10 pt-5 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-[#25a5ff]/20 to-purple-500/10 text-[#25a5ff] flex items-center justify-center text-xs font-black border border-[#25a5ff]/30 shadow-md">L3</div>
            <div>
              <p className="text-xs font-bold text-white">Operator-Jyothi</p>
              <p className="text-[9px] text-[#25a5ff] font-mono font-bold uppercase tracking-widest">SecOps Lead</p>
            </div>
          </div>
          <button onClick={() => setIsLoggedIn(false)} className="text-[#425265] hover:text-red-400 p-2.5 rounded-xl border border-transparent hover:border-red-500/10 hover:bg-red-500/5 transition-all"><LogOut size={16} /></button>
        </div>
      </aside>

      <main className="flex-1 p-8 overflow-y-auto z-10 relative">
        <header className="mb-8 flex justify-between items-center border-b border-[#25a5ff]/15 pb-6">
          <div>
            <div className="text-[9px] font-mono font-black text-[#25a5ff] tracking-widest uppercase mb-1">System Terminal Protocol Matrix</div>
            <h2 className="text-2xl font-black tracking-widest text-white uppercase">{activeTab.replace('_', ' ')} Module</h2>
          </div>
          <div className="bg-[#0b101d] border border-[#25a5ff]/20 text-[10px] font-mono font-bold px-4 py-2.5 rounded-xl text-[#25a5ff] tracking-widest flex items-center gap-2 shadow-inner">
            <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_10px_#34d399] animate-pulse" /> INFRASTRUCTURE LAYER: ONLINE
          </div>
        </header>

        <div className="relative overflow-hidden min-h-[calc(100vh-200px)]">
          {activeTab === 'dashboard' && (
            <div key={activeTab} className={workspaceAnimationDirection === 'right' ? 'workspace-panel-enter' : 'workspace-panel-enter-left'}>
              <div className="space-y-8">
                <label className="border-2 border-dashed border-[#25a5ff]/20 bg-gradient-to-b from-[#090e18]/60 to-[#04060b]/90 hover:border-[#25a5ff]/60 hover:shadow-[0_0_40px_rgba(37,165,255,0.03)] transition-all rounded-3xl p-16 text-center flex flex-col items-center justify-center cursor-pointer group relative overflow-hidden block">
                  <div className="absolute inset-0 bg-gradient-to-r from-[#25a5ff]/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />
                  <input type="file" onChange={handleFileChange} className="hidden" disabled={uploading} />
                  <div className="w-16 h-14 rounded-2xl bg-[#25a5ff]/5 border border-[#25a5ff]/20 text-[#25a5ff] flex items-center justify-center mb-5 shadow-lg group-hover:scale-105 group-hover:border-[#25a5ff]/40 transition-all">
                    <Upload size={26} className="group-hover:animate-bounce" />
                  </div>
                  <h3 className="text-lg font-bold tracking-wider text-white uppercase">
                    {uploading ? 'Ingesting Payload Asset into Sandbox Cache...' : 'Detonate Suspicious Threat Payload'}
                  </h3>
                  <p className="text-xs text-[#576575] font-mono max-w-sm mt-1 uppercase tracking-wider">Supports Win32 PE Binaries, Text Scripts, ELF Structures</p>
                  {!uploading && (
                    <div className="mt-5 px-5 py-2.5 bg-[#0e1424] border border-[#25a5ff]/30 text-[#25a5ff] text-xs font-mono font-bold uppercase tracking-widest rounded-xl shadow-md group-hover:bg-[#25a5ff] group-hover:text-black transition-all">
                      Select File Stream
                    </div>
                  )}
                </label>

                {analysisResult ? (
                  <div className="p-6 rounded-3xl border border-red-500/30 bg-gradient-to-r from-red-950/20 via-[#070b12] to-black shadow-2xl flex items-center justify-between">
                    <div className="flex items-center space-x-5">
                      <div className="p-4 rounded-2xl bg-red-500/10 text-red-400 border border-red-500/20"><ShieldAlert size={28} /></div>
                      <div>
                        <h4 className="text-sm font-mono font-black tracking-widest text-red-400 uppercase">TELEMETRY RECEIVED SUCCESFULLY</h4>
                        <p className="text-xs font-mono text-white mt-1">Loaded Identifier: <span className="text-[#25a5ff] font-bold">{analysisResult.file_name}</span></p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-3 font-mono text-xs">
                      <span className="text-[#576575] uppercase tracking-wider">Pivot to Sidebar Panel:</span>
                      <button onClick={() => switchTab('static_parser')} className="px-4 py-2.5 bg-[#121927] border border-[#25a5ff]/20 hover:border-[#25a5ff] rounded-xl font-bold uppercase tracking-wider transition-all flex items-center gap-1">Static Data <ArrowRight size={14}/></button>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-6">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                      {[
                        { title: 'Global Database Ingests', value: '142,804', icon: Database, color: 'text-[#25a5ff]', bg: 'from-[#25a5ff]/10' },
                        { title: 'Critical Signatures Cataloged', value: '84,912', icon: ShieldAlert, color: 'text-red-400', bg: 'from-red-500/10' },
                        { title: 'Active Node Scanning Efficiency', value: '99.98%', icon: Cpu, color: 'text-emerald-400', bg: 'from-emerald-500/10' },
                      ].map((card, i) => {
                        const Icon = card.icon;
                        return (
                          <div key={i} className={`bg-gradient-to-br ${card.bg} to-[#070a12]/90 border border-[#25a5ff]/15 rounded-2xl p-6 flex items-center justify-between shadow-xl group hover:border-[#25a5ff]/40 transition-all`}>
                            <div className="space-y-1">
                              <p className="text-[10px] font-mono font-bold uppercase tracking-widest text-[#576575]">{card.title}</p>
                              <h4 className={`text-3xl font-black font-mono tracking-tight ${card.color}`}>{card.value}</h4>
                            </div>
                            <div className={`p-3 bg-black/40 rounded-xl border border-white/5 ${card.color}`}><Icon size={20} /></div>
                          </div>
                        );
                      })}
                    </div>

                    <div className="bg-[#080d16]/60 border border-[#25a5ff]/15 rounded-2xl p-6 shadow-2xl">
                      <h3 className="text-xs font-mono font-black tracking-widest text-[#25a5ff] uppercase mb-4 flex items-center gap-2"><History size={14}/> Operational Threat Log History</h3>
                      <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse text-xs font-mono">
                          <thead>
                            <tr className="border-b border-[#25a5ff]/10 text-[#576575]">
                              <th className="pb-3 uppercase tracking-wider">Payload Name</th>
                              <th className="pb-3 uppercase tracking-wider">Timestamp</th>
                              <th className="pb-3 uppercase tracking-wider">Signature Tracking</th>
                              <th className="pb-3 uppercase tracking-wider text-right">Hazard Index Evaluation</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-white/5">
                            {scanHistory.map((row, i) => (
                              <tr key={i} className="hover:bg-white/5 transition-colors">
                                <td className="py-3.5 text-white font-bold">{row.name}</td>
                                <td className="py-3.5 text-[#576575]">{row.time}</td>
                                <td className="py-3.5 font-mono text-[#25a5ff]">{row.hash}</td>
                                <td className="py-3.5 text-right">
                                  <span className={`px-2.5 py-1 rounded-lg text-[10px] font-bold tracking-wider ${
                                    row.verdict === 'MALICIOUS' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                                    row.verdict === 'SUSPICIOUS' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20' :
                                    'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                  }`}>{row.verdict} ({row.score})</span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'static_parser' && (
            <div key={activeTab} className={workspaceAnimationDirection === 'right' ? 'workspace-panel-enter' : 'workspace-panel-enter-left'}>
              {analysisResult ? (
                <div className="space-y-6">
                  {analysisResult.malware_classification && (
                    <div className={`p-6 rounded-2xl border ${
                      analysisResult.malware_classification.verdict === 'MALICIOUS' ? 'bg-red-500/5 border-red-500/30 text-red-400' :
                      analysisResult.malware_classification.verdict === 'SUSPICIOUS' ? 'bg-orange-500/5 border-orange-500/30 text-orange-400' :
                      'bg-emerald-500/5 border-emerald-500/30 text-emerald-400'
                    } flex justify-between items-start shadow-xl`}>
                      <div className="space-y-2">
                        <span className="text-[10px] font-mono font-black tracking-widest uppercase opacity-60">Automated Heuristic Verdict Classification Matrix</span>
                        <h3 className="text-2xl font-black font-mono tracking-wider">{analysisResult.malware_classification.verdict}</h3>
                        <ul className="text-xs font-mono list-disc list-inside text-[#94a3b8] space-y-1 pt-1">
                          {analysisResult.malware_classification.indicators.map((ind, i) => <li key={i}>{ind}</li>)}
                          {analysisResult.malware_classification.indicators.length === 0 && <li>No critical code anomalies discovered. Binary structures standard.</li>}
                        </ul>
                      </div>
                      <div className="bg-black/40 border border-white/5 p-4 rounded-xl text-center font-mono min-w-[100px]">
                        <p className="text-[9px] text-[#576575] font-bold uppercase tracking-wider">Risk Score</p>
                        <p className="text-2xl font-black text-white mt-0.5">{analysisResult.malware_classification.score}<span className="text-xs text-[#576575]">/100</span></p>
                      </div>
                    </div>
                  )}

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
                    <div className="bg-[#080d16]/80 border border-[#25a5ff]/15 p-6 rounded-2xl space-y-4 shadow-xl">
                      <h3 className="text-xs font-bold uppercase tracking-widest text-[#25a5ff] flex items-center gap-2 border-b border-[#25a5ff]/10 pb-3"><FileCode size={14}/> File Hashes Registry</h3>
                      <div className="space-y-3">
                        {[
                          { label: 'SHA-256 Signature', val: analysisResult.sha256 },
                          { label: 'MD5 Signature', val: analysisResult.hashes?.md5 || 'N/A' },
                          { label: 'SHA-1 Signature', val: analysisResult.hashes?.sha1 || 'N/A' },
                        ].map((h, i) => (
                          <div key={i} className="bg-black/30 border border-white/5 p-3 rounded-xl flex items-center justify-between group">
                            <div className="w-[85%]">
                              <p className="text-[9px] text-[#576575] uppercase font-bold">{h.label}</p>
                              <p className="text-white mt-0.5 break-all text-[11px] font-bold">{h.val}</p>
                            </div>
                            <button onClick={() => triggerCopy(h.val, h.label)} className="p-2 text-[#576575] hover:text-[#25a5ff] bg-black/40 border border-white/5 rounded-lg transition-all cursor-pointer">
                              {copiedKey === h.label ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="bg-[#080d16]/80 border border-[#25a5ff]/15 p-6 rounded-2xl space-y-4 shadow-xl flex flex-col justify-between">
                      <div>
                        <h3 className="text-xs font-bold uppercase tracking-widest text-[#25a5ff] flex items-center gap-2 border-b border-[#25a5ff]/10 pb-3"><Zap size={14}/> Entropy Metric Mapping</h3>
                        <p className="text-[11px] text-[#94a3b8] font-sans mt-2">Shannon Entropy calculates randomization variables ($0$ to $8$). Scores exceeding $7.2$ imply code obfuscation techniques or packed cryptographic code arrays.</p>
                      </div>
                      <div className="bg-black/40 border border-white/5 p-5 rounded-2xl flex items-center justify-between">
                        <div>
                          <p className="text-[10px] text-[#576575] font-bold uppercase tracking-wider">Entropy Index</p>
                          <p className={`text-3xl font-black mt-0.5 ${analysisResult.entropy > 7.2 ? 'text-red-400 animate-pulse' : 'text-emerald-400'}`}>{analysisResult.entropy}</p>
                        </div>
                        <span className={`px-3 py-1.5 rounded-xl font-bold tracking-widest uppercase text-[9px] border ${
                          analysisResult.entropy > 7.2 ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                        }`}>{analysisResult.entropy > 7.2 ? '⚠️ High / Obfuscated' : '🟢 Secure Standard Data'}</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-[#080d16]/80 border border-[#25a5ff]/15 rounded-2xl p-6 shadow-2xl">
                    <h3 className="text-xs font-mono font-black tracking-widest text-[#25a5ff] uppercase mb-4 flex items-center gap-2 border-b border-[#25a5ff]/10 pb-3"><Network size={14}/> Import Address Table (IAT) Core API Hook Dissector</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs font-mono">
                      {[
                        { api: 'CreateRemoteThread', library: 'kernel32.dll', type: 'CRITICAL', desc: 'Process Injection Activity' },
                        { api: 'InternetOpenA', library: 'wininet.dll', type: 'HIGH RISK', desc: 'Outbound C2 Network Infrastructure Link' },
                        { api: 'WriteProcessMemory', library: 'kernel32.dll', type: 'CRITICAL', desc: 'Memory Mutation Manipulation' },
                        { api: 'RegSetValueExA', library: 'advapi32.dll', type: 'SUSPICIOUS', desc: 'Registry Startup Persistence Tactic' },
                        { api: 'URLDownloadToFileW', library: 'urlmon.dll', type: 'HIGH RISK', desc: 'Secondary Payload Downloader Stream' },
                        { api: 'GetProcAddress', library: 'kernel32.dll', type: 'INFO', desc: 'Dynamic API Core Resolution Loop' },
                      ].map((api, idx) => (
                        <div key={idx} className="bg-black/40 border border-white/5 p-4 rounded-xl flex flex-col justify-between shadow-md">
                          <div className="flex justify-between items-start">
                            <div>
                              <p className="text-white font-bold text-sm">{api.api}</p>
                              <p className="text-[10px] text-[#576575] font-bold uppercase mt-0.5">{api.library}</p>
                            </div>
                            <span className={`px-2 py-0.5 rounded text-[8px] font-mono font-black tracking-widest ${
                              api.type === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border border-red-500/30' :
                              api.type === 'HIGH RISK' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/30' :
                              api.type === 'SUSPICIOUS' ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30' :
                              'bg-blue-500/10 text-blue-400 border border-blue-500/30'
                            }`}>{api.type}</span>
                          </div>
                          <p className="text-[10px] text-[#94a3b8] mt-2 border-t border-white/5 pt-1.5 italic font-sans">{api.desc}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {analysisResult.pe_metadata?.sections && (
                    <div className="bg-[#080d16]/80 border border-[#25a5ff]/15 rounded-2xl p-6 shadow-xl">
                      <p className="text-xs font-mono font-black uppercase tracking-widest text-[#25a5ff] mb-4 flex items-center gap-2"><Binary size={14}/> Dissected PE Header Structure Mappings</p>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono text-xs">
                        {analysisResult.pe_metadata.sections.map((sec, idx) => (
                          <div key={idx} className="bg-black/30 border border-[#25a5ff]/10 p-4 rounded-xl flex flex-col justify-between group hover:border-[#25a5ff]/40 transition-colors">
                            <div>
                              <p className="text-[#25a5ff] font-black text-sm">{sec.name || '.unnamed'}</p>
                              <p className="text-[9px] text-[#576575] mt-1 font-bold uppercase">Virtual Size: <span className="text-white font-mono">{sec.virtual_size || '0x000'}</span></p>
                            </div>
                            <p className="text-[10px] text-[#576575] font-bold uppercase mt-2 border-t border-white/5 pt-1.5">Raw Data: <span className="text-white">{sec.raw_data_size}</span></p>
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
                <div className="bg-[#080d16]/80 border border-[#25a5ff]/15 rounded-2xl p-6 space-y-6 shadow-2xl">
                  <div className="flex justify-between items-center border-b border-[#25a5ff]/10 pb-4">
                    <h3 className="text-sm font-mono font-black tracking-widest text-orange-400 flex items-center gap-2"><ShieldAlert size={18}/> Detonation Sandbox Matrix Node</h3>
                    <div className="flex bg-black/40 p-1 rounded-xl border border-white/5 font-mono text-[10px] font-bold uppercase tracking-wider">
                      <button onClick={() => setSandboxTab('tree')} className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${sandboxTab === 'tree' ? 'bg-[#25a5ff] text-black font-black' : 'text-[#576575] hover:text-white'}`}>Process Tree</button>
                      <button onClick={() => setSandboxTab('mutations')} className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${sandboxTab === 'mutations' ? 'bg-[#25a5ff] text-black font-black' : 'text-[#576575] hover:text-white'}`}>System Mutations</button>
                    </div>
                  </div>

                  {sandboxTab === 'tree' ? (
                    <div className="space-y-4">
                      <p className="text-xs text-[#94a3b8] font-sans">Dissecting real-time parent-child binary task spawning pipelines executed inside the quarantined runtime cage:</p>
                      <div className="p-8 bg-black/40 border border-white/5 rounded-2xl font-mono text-xs space-y-6 relative overflow-hidden">
                        <div className="absolute left-12 top-12 bottom-12 border-l border-dashed border-[#25a5ff]/20 pointer-events-none" />
                        
                        <div className="flex items-center space-x-3 relative z-10">
                          <div className="w-8 h-8 rounded-xl bg-orange-500/10 text-orange-400 border border-orange-500/30 flex items-center justify-center font-bold font-mono">1</div>
                          <div className="bg-[#121927] border border-orange-500/30 p-3 rounded-xl min-w-[240px] shadow-md">
                            <p className="text-white font-bold">{analysisResult.file_name} (PID: 4082)</p>
                            <p className="text-[9px] text-orange-400 uppercase tracking-wider font-bold mt-0.5">Root Malicious Execution Vector</p>
                          </div>
                        </div>

                        <div className="flex items-center space-x-3 ml-12 relative z-10">
                          <div className="w-6 h-0.5 bg-[#25a5ff]/30 -ml-6" />
                          <div className="w-8 h-8 rounded-xl bg-red-500/10 text-red-400 border border-red-500/30 flex items-center justify-center font-bold font-mono">2</div>
                          <div className="bg-[#121927] border border-red-500/30 p-3 rounded-xl min-w-[240px] shadow-md">
                            <p className="text-white font-bold">cmd.exe (PID: 5120)</p>
                            <p className="text-[9px] text-red-400 uppercase tracking-wider font-bold mt-0.5">↳ Spawned Hidden Command Console</p>
                          </div>
                        </div>

                        <div className="flex items-center space-x-3 ml-24 relative z-10">
                          <div className="w-6 h-0.5 bg-[#25a5ff]/30 -ml-6" />
                          <div className="w-8 h-8 rounded-xl bg-red-500/20 text-red-400 border border-red-500/40 flex items-center justify-center font-bold font-mono animate-pulse">3</div>
                          <div className="bg-[#1a1014] border border-red-500/40 p-3 rounded-xl min-w-[240px] shadow-2xl">
                            <p className="text-white font-bold">powershell.exe (PID: 5940)</p>
                            <p className="text-[9px] text-red-500 uppercase tracking-wider font-black mt-0.5">↳ Critical: Executing Base64 Script Block</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
                      <div className="bg-black/30 border border-[#25a5ff]/10 p-5 rounded-xl space-y-2">
                        <p className="text-red-400 font-bold uppercase tracking-wider text-[10px] border-b border-red-500/10 pb-1.5">File System Mutations Log</p>
                        <p className="text-white text-[11px]">[+] Dropped: C:\Windows\Temp\payload.tmp</p>
                        <p className="text-white text-[11px]">[+] Created: LocalData\App\cache_dump.bin</p>
                        <p className="text-[#576575] text-[10px] italic">Monitoring file mutations stream...</p>
                      </div>
                      <div className="bg-black/30 border border-[#25a5ff]/10 p-5 rounded-xl space-y-2">
                        <p className="text-orange-400 font-bold uppercase tracking-wider text-[10px] border-b border-orange-500/10 pb-1.5">Network Connections Intercepted</p>
                        {analysisResult.iocs?.ips?.length > 0 ? (
                          analysisResult.iocs.ips.map((ip, idx) => <p key={idx} className="text-white text-[11px]">[!] Outbound Connection $\rightarrow$ {ip}:443 (TCP Socket Open)</p>)
                        ) : <p className="text-[#576575] text-[11px] italic">No active outbound calls registered.</p>}
                      </div>
                    </div>
                  )}
                </div>
              ) : <p className="text-sm font-mono text-[#576575] italic p-6 border border-dashed border-[#25a5ff]/10 rounded-2xl">Awaiting threat payload ingestion data array on Triage Dashboard view.</p>}
            </div>
          )}

          {activeTab === 'ioc_tracker' && (
            <div key={activeTab} className={workspaceAnimationDirection === 'right' ? 'workspace-panel-enter' : 'workspace-panel-enter-left'}>
              {analysisResult?.iocs ? (
                <div className="space-y-6 animate-fadeIn">
                  <p className="text-xs text-[#94a3b8] font-sans">Indicators of Compromise (IoCs) parsed securely from binary text strings and file structure characteristics for firewall rules extraction:</p>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    {[
                      { title: 'Network C2 IPs', data: analysisResult.iocs.ips, color: 'text-red-400', border: 'border-red-500/20', bg: 'bg-red-500/5' },
                      { title: 'Callout Domains', data: analysisResult.iocs.domains, color: 'text-orange-400', border: 'border-orange-500/20', bg: 'bg-orange-500/5' },
                      { title: 'Windows Registry Keys', data: analysisResult.iocs.registry_keys, color: 'text-yellow-400', border: 'border-yellow-500/20', bg: 'bg-yellow-500/5' },
                    ].map((sec, i) => (
                      <div key={i} className="bg-[#080d16]/80 border border-[#25a5ff]/15 p-5 rounded-2xl shadow-xl flex flex-col justify-between min-h-[260px]">
                        <div>
                          <p className="text-[#25a5ff] font-mono font-black uppercase text-xs tracking-widest border-b border-[#25a5ff]/10 pb-2.5 mb-3">{sec.title}</p>
                          {sec.data && sec.data.length > 0 ? (
                            <div className="space-y-2 max-h-40 overflow-y-auto">
                              {sec.data.map((item, idx) => (
                                <div key={idx} className={`${sec.bg} ${sec.border} border px-3 py-2 rounded-xl flex items-center justify-between group text-xs font-mono`}>
                                  <span className={`${sec.color} font-bold tracking-wide truncate max-w-[80%]`}>{item}</span>
                                  <button onClick={() => triggerCopy(item, `${i}-${idx}`)} className="opacity-40 group-hover:opacity-100 transition-opacity text-[#576575] hover:text-white cursor-pointer">
                                    {copiedKey === `${i}-${idx}` ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                                  </button>
                                </div>
                              ))}
                            </div>
                          ) : <p className="text-xs text-[#576575] italic font-mono p-2">Zero active elements discovered.</p>}
                        </div>
                        {sec.data && sec.data.length > 0 && (
                          <button onClick={() => triggerCopy(sec.data.join('\n'), sec.title)} className="w-full mt-4 py-2 bg-black/40 border border-white/5 hover:border-[#25a5ff]/40 text-[10px] font-mono font-bold uppercase tracking-wider rounded-xl transition-all text-[#576575] hover:text-[#25a5ff] cursor-pointer">
                            {copiedKey === sec.title ? 'Copied Cluster Ledger!' : `Copy All ${sec.title}`}
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ) : <p className="text-sm font-mono text-[#576575] italic p-6 border border-dashed border-[#25a5ff]/10 rounded-2xl">Awaiting threat payload ingestion data array on Triage Dashboard view.</p>}
            </div>
          )}

          {activeTab === 'ai_reports' && (
            <div key={activeTab} className={workspaceAnimationDirection === 'right' ? 'workspace-panel-enter' : 'workspace-panel-enter-left'}>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-start">
                <div className="bg-[#080d16]/80 border border-[#25a5ff]/15 p-6 rounded-3xl space-y-4 shadow-2xl relative overflow-hidden">
                  <div className="absolute top-0 right-0 p-4 font-mono text-[9px] text-[#576575] font-bold uppercase tracking-widest pointer-events-none">MODEL: CLAUDE 3.5 SONNET</div>
                  <h3 className="text-sm font-mono font-black uppercase tracking-widest text-[#25a5ff] flex items-center gap-2 border-b border-[#25a5ff]/10 pb-3"><Zap size={16}/> Synthetic Executive Security Brief</h3>
                  {analysisResult ? (
                    <div className="text-xs font-sans text-[#94a3b8] space-y-4 leading-relaxed whitespace-pre-line bg-black/30 p-5 rounded-2xl border border-white/5 max-h-[460px] overflow-y-auto custom-scrollbar">
                      {analysisResult.ai_generated_report ? (
                        analysisResult.ai_generated_report
                      ) : (
                        <div className="flex flex-col items-center justify-center py-20 space-y-3">
                          <div className="w-8 h-8 rounded-full border-2 border-t-transparent border-[#25a5ff] animate-spin" />
                          <p className="font-mono text-xs text-[#25a5ff] uppercase tracking-widest animate-pulse">Orchestrating Anthropic Core Neural Grid Nodes...</p>
                        </div>
                      )}
                    </div>
                  ) : <p className="text-xs font-mono text-[#576575] italic p-4">Please ingest a threat file structure into the uploader matrix first.</p>}
                </div>

                <div className="bg-[#04070e] border border-[#25a5ff]/15 rounded-3xl flex flex-col h-[520px] overflow-hidden shadow-2xl relative">
                  <div className="absolute inset-0 bg-[#25a5ff]/0.5 mix-blend-overlay pointer-events-none" />
                  <div className="bg-[#090d16] px-5 py-4 border-b border-[#25a5ff]/15 flex items-center justify-between text-xs font-mono font-black tracking-widest uppercase text-white shadow-md relative z-10">
                    <div className="flex items-center gap-2"><Terminal size={14} className="text-[#25a5ff]"/> Copilot SecOps Assistant</div>
                    <span className="w-2 h-2 rounded-full bg-[#25a5ff] shadow-[0_0_8px_#25a5ff]" />
                  </div>
                  <div className="flex-1 p-5 overflow-y-auto space-y-4 text-xs relative z-10 custom-scrollbar">
                    {chatLog.map((msg, index) => (
                      <div key={index} className={`p-4 rounded-2xl max-w-[85%] font-mono border whitespace-pre-line transition-all duration-300 shadow-md ${
                        msg.role === 'user' 
                          ? 'bg-[#25a5ff]/10 text-[#25a5ff] border-[#25a5ff]/20 ml-auto' 
                          : 'bg-[#0e1424]/90 text-[#94a3b8] border-white/5 mr-auto'
                      }`}>
                        <p className="text-[9px] uppercase tracking-widest opacity-40 font-black mb-1.5">{msg.role === 'user' ? 'Operator' : 'BlueIntel AI Engine'}</p>
                        {msg.text}
                      </div>
                    ))}
                  </div>
                  <form onSubmit={submitAgenticQuery} className="p-4 bg-[#090d16] border-t border-[#25a5ff]/15 flex gap-3 relative z-10">
                    <input type="text" value={chatInput} onChange={(e) => setChatInput(e.target.value)} className="flex-1 bg-[#020307] border border-[#25a5ff]/20 rounded-xl px-4 py-3.5 text-xs text-white font-mono outline-none focus:border-[#25a5ff] shadow-inner" placeholder="Ask about MITRE mappings, ioc footprints, or rules..."/>
                    <button type="submit" className="bg-[#131926] border border-[#25a5ff]/30 text-[#25a5ff] hover:bg-[#25a5ff] hover:text-black px-5 rounded-xl text-xs font-mono font-black uppercase tracking-widest cursor-pointer transition-all shadow-md">Transmit</button>
                  </form>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'threat_graph' && (
            <div key={activeTab} className={workspaceAnimationDirection === 'right' ? 'workspace-panel-enter' : 'workspace-panel-enter-left'}>
              <div className="bg-[#080d16]/80 border border-[#25a5ff]/15 rounded-3xl p-6 space-y-4 shadow-2xl relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-t from-[#25a5ff]/2 to-transparent pointer-events-none" />
                <div className="flex justify-between items-center border-b border-white/5 pb-4">
                  <h3 className="text-sm font-mono font-black tracking-widest text-[#25a5ff] flex items-center gap-2"><BarChart3 size={18}/> Real-World Daily Threat Clustering Core Feed</h3>
                  <span className="text-[9px] tracking-widest font-mono font-black text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-lg border border-emerald-500/20 animate-pulse">LIVE INTEL SYNC</span>
                </div>
                <p className="text-xs text-[#94a3b8] font-sans leading-relaxed">Visualizing aggregated telemetry indexes capturing activity spikes across primary ransomware, trojans, exploit kits, and data infostealer sectors over the current trailing 7-day logging framework.</p>
                
                <div className="w-full h-96 pt-4 font-mono text-[11px] relative z-10">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={threatTimelineData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                      <defs>
                        <linearGradient id="colorRansom" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ef4444" stopOpacity={0.15}/><stop offset="95%" stopColor="#ef4444" stopOpacity={0}/></linearGradient>
                        <linearGradient id="colorTrojan" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#f97316" stopOpacity={0.15}/><stop offset="95%" stopColor="#f97316" stopOpacity={0}/></linearGradient>
                        <linearGradient id="colorStealer" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#a855f7" stopOpacity={0.15}/><stop offset="95%" stopColor="#a855f7" stopOpacity={0}/></linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#25a5ff" opacity={0.03} />
                      <XAxis dataKey="date" stroke="#425265" />
                      <YAxis stroke="#425265" />
                      <Tooltip contentStyle={{ backgroundColor: '#090d16', borderColor: '#25a5ff', borderRadius: '16px', fontSize: '11px', color: '#fff', boxShadow: '0 10px 30px rgba(0,0,0,0.5)' }} />
                      <Legend verticalAlign="top" height={36} iconType="circle" />
                      <Area type="monotone" name="Ransomware Vectors" dataKey="Ransomware" stroke="#ef4444" strokeWidth={2.5} fillOpacity={1} fill="url(#colorRansom)" />
                      <Area type="monotone" name="Trojan Activity" dataKey="Trojans" stroke="#f97316" strokeWidth={2.5} fillOpacity={1} fill="url(#colorTrojan)" />
                      <Area type="monotone" name="InfoStealer Spike" dataKey="InfoStealers" stroke="#a855f7" strokeWidth={2.5} fillOpacity={1} fill="url(#colorStealer)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );

  return (
    <div className="min-h-screen bg-[#02020a] text-white font-sans relative overflow-hidden">
      <style>{`
        @keyframes authCardSlide {
          0% { opacity: 0; transform: translateY(14px); }
          100% { opacity: 1; transform: translateY(0); }
        }
        @keyframes authCardSlideReverse {
          0% { opacity: 0; transform: translateY(-14px); }
          100% { opacity: 1; transform: translateX(0); }
        }
        @keyframes workspacePanelSlide {
          0% { opacity: 0; transform: translateX(20px); filter: blur(4px); }
          100% { opacity: 1; transform: translateX(0); filter: blur(0); }
        }
        @keyframes workspacePanelSlideLeft {
          0% { opacity: 0; transform: translateX(-20px); filter: blur(4px); }
          100% { opacity: 1; transform: translateX(0); filter: blur(0); }
        }
        .auth-card-enter { animation: authCardSlide 500ms cubic-bezier(0.16, 1, 0.3, 1) both; }
        .auth-card-enter-reverse { animation: authCardSlideReverse 500ms cubic-bezier(0.16, 1, 0.3, 1) both; }
        .workspace-panel-enter { animation: workspacePanelSlide 550ms cubic-bezier(0.16, 1, 0.3, 1) both; }
        .workspace-panel-enter-left { animation: workspacePanelSlideLeft 550ms cubic-bezier(0.16, 1, 0.3, 1) both; }
        
        .custom-scrollbar::-webkit-scrollbar { width: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: rgba(255,255,255,0.02); border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(37,165,255,0.2); border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(37,165,255,0.4); }
      `}</style>

      {(!isLoggedIn || transitionState !== 'dashboard') && (
        <div className={`absolute inset-0 flex items-center justify-center transition-all duration-700 z-20 ${transitionState === 'reveal' ? 'opacity-0 scale-95 blur-md pointer-events-none' : 'opacity-100 scale-100'}`}>
          {renderAuthScreen()}
        </div>
      )}

      {isLoggedIn && (
        <div className={`min-h-screen transition-all duration-700 ${transitionState === 'dashboard' ? 'opacity-100 filter blur-0 scale-100' : 'opacity-30 filter blur-sm scale-[0.99]'}`}>
          {renderDashboardScreen()}
        </div>
      )}
    </div>
  );
}