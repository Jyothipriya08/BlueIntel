import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Cpu, Binary, Brain, ShieldAlert, FileText, BarChart3, ArrowRight, Activity, Terminal } from 'lucide-react';

export default function Landing() {
  const navigate = useNavigate();
  const [scrolled, setScrolled] = useState(false);
  const [metrics, setMetrics] = useState({ analyzed: 0, detected: 0, accuracy: 0 });

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', handleScroll);
    
    // Smooth statistics counter interpolation animation
    const interval = setInterval(() => {
      setMetrics(prev => ({
        analyzed: prev.analyzed < 142804 ? Math.min(prev.analyzed + 3500, 142804) : 142804,
        detected: prev.detected < 84912 ? Math.min(prev.detected + 2100, 84912) : 84912,
        accuracy: prev.accuracy < 99.98 ? Math.min(prev.accuracy + 2.5, 99.98) : 99.98
      }));
    }, 30);

    return () => {
      window.removeEventListener('scroll', handleScroll);
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="min-h-screen bg-[#02020a] text-white font-sans selection:bg-[#25a5ff]/30 selection:text-white overflow-x-hidden">
      {/* Dynamic Animated Particle Canvas Overlay */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,_var(--tw-gradient-stops))] from-[#0f172a] via-[#02020a] to-[#02020a] pointer-events-none z-0" />
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[800px] h-[350px] bg-gradient-to-r from-[#25a5ff]/10 to-purple-600/5 rounded-full blur-[160px] pointer-events-none z-0 animate-pulse" />

      {/* Sticky Top Navbar */}
      <nav className={`fixed top-0 w-full z-50 transition-all duration-300 ${scrolled ? 'bg-[#060b13]/80 backdrop-blur-xl border-b border-[#25a5ff]/15 py-4' : 'bg-transparent py-6'}`}>
        <div className="max-w-7xl mx-auto px-6 flex justify-between items-center">
          <div className="flex items-center space-x-3">
            <Shield className="text-[#25a5ff] h-6 w-6" />
            <span className="font-black text-xl tracking-widest uppercase">BLUE<span className="text-[#25a5ff]">INTEL</span></span>
          </div>
          <div className="hidden md:flex space-x-8 font-mono text-xs uppercase tracking-wider text-[#576575]">
            <a href="#features" className="hover:text-white transition-colors">Features</a>
            <a href="#workflow" className="hover:text-white transition-colors">Workflow</a>
            <a href="#metrics" className="hover:text-white transition-colors">Telemetry</a>
          </div>
          <div className="flex items-center space-x-4">
            <button onClick={() => navigate('/login')} className="px-5 py-2.5 text-xs font-mono font-bold uppercase tracking-widest border border-[#25a5ff]/30 text-white rounded-xl hover:bg-[#25a5ff]/10 transition-all cursor-pointer">
              Sign In
            </button>
            <button onClick={() => navigate('/signup')} className="px-5 py-2.5 text-xs font-mono font-bold uppercase tracking-widest bg-gradient-to-r from-[#1e3a8a] to-[#25a5ff] text-white rounded-xl shadow-[0_4px_20px_rgba(37,165,255,0.2)] hover:scale-105 transition-all cursor-pointer">
              Get Started
            </button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative min-h-screen flex items-center justify-center pt-32 px-6 z-10">
        <div className="max-w-4xl mx-auto text-center space-y-8">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-[#25a5ff]/5 border border-[#25a5ff]/20 text-[#25a5ff] text-[10px] font-mono font-bold tracking-widest uppercase animate-pulse">
            <Terminal size={12} /> AI-Powered Malware Analysis Platform
          </div>
          <h1 className="text-5xl md:text-7xl font-black tracking-tight leading-none text-white uppercase bg-clip-text text-transparent bg-gradient-to-b from-white via-slate-200 to-slate-400">
            Analyze, Detect, <br />Investigate & Respond
          </h1>
          <p className="text-sm md:text-base text-[#576575] font-mono max-w-2xl mx-auto tracking-wide leading-relaxed">
            "Analyze, Detect, Investigate and Respond to Malware Threats using Artificial Intelligence." Engineered for instantaneous static unpacking, dynamic process virtualization, and neural signature playbooks.
          </p>
          <div className="flex flex-col sm:flex-row justify-center items-center gap-4 pt-4">
            <button onClick={() => navigate('/login')} className="w-full sm:w-auto px-8 py-4 font-mono font-bold uppercase tracking-widest text-xs rounded-xl bg-[#25a5ff] text-black hover:bg-white hover:shadow-[0_0_30px_#25a5ff] transition-all flex items-center justify-center gap-2 group cursor-pointer">
              Access Security Console <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
            </button>
          </div>
        </div>
      </section>

      {/* Enterprise Features Grid */}
      <section id="features" className="py-32 max-w-7xl mx-auto px-6 relative z-10 border-t border-white/5">
        <div className="text-center space-y-3 mb-20">
          <p className="text-[10px] font-mono font-black tracking-widest text-[#25a5ff] uppercase">Core Capability Blueprint</p>
          <h2 className="text-3xl font-black uppercase tracking-wider">Defensive Tactical Architecture</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {[
            { title: 'Static Malware Analysis', desc: 'Instant binary structural parsing, IAT hook mapping, section validation, and hash extraction.', icon: Binary },
            { title: 'AI Threat Classification', desc: 'Direct compilation of reverse-engineered telemetry via advanced neural logic blocks.', icon: Brain },
            { title: 'YARA Detection Layer', desc: 'Automated signature string pattern discovery leveraging standard execution rulesets.', icon: ShieldAlert },
          ].map((feat, idx) => {
            const Icon = feat.icon;
            return (
              <div key={idx} className="backdrop-blur-md bg-[#090d16]/40 border border-[#25a5ff]/15 p-8 rounded-2xl hover:border-[#25a5ff]/40 transition-all group shadow-xl">
                <div className="w-12 h-12 rounded-xl bg-[#25a5ff]/5 border border-[#25a5ff]/20 text-[#25a5ff] flex items-center justify-center mb-6 group-hover:bg-[#25a5ff] group-hover:text-black transition-all">
                  <Icon size={20} />
                </div>
                <h3 className="text-sm font-mono font-black uppercase text-white mb-2 tracking-wider">{feat.title}</h3>
                <p className="text-xs text-[#576575] leading-relaxed font-sans">{feat.desc}</p>
              </div>
            );
          })}
        </div>
      </section>

      {/* Timeline Workflow Section */}
      <section id="workflow" className="py-32 max-w-5xl mx-auto px-6 relative z-10 border-t border-white/5">
        <div className="text-center space-y-3 mb-20">
          <p className="text-[10px] font-mono font-black tracking-widest text-[#25a5ff] uppercase">Telemetry Pipeline</p>
          <h2 className="text-3xl font-black uppercase tracking-wider">Ingestion Workflow Timeline</h2>
        </div>
        <div className="flex flex-col md:flex-row items-center justify-between gap-6 font-mono text-xs">
          {['Upload File Asset', 'Deconstruct Data Arrays', 'AI Engine Classification', 'Threat Intelligence Sync', 'Generate Security Playbook'].map((step, i) => (
            <React.Fragment key={i}>
              <div className="bg-[#090d16]/70 border border-[#25a5ff]/20 px-5 py-4 rounded-xl shadow-md font-bold text-center min-w-[180px]">
                <span className="text-[#25a5ff] block mb-1">NODE 0{i+1}</span>
                {step}
              </div>
              {i < 4 && <ArrowRight className="hidden md:block text-[#25a5ff]/40 animate-pulse shrink-0" />}
            </React.Fragment>
          ))}
        </div>
      </section>

      {/* Animated Metrics Feed Section */}
      <section id="metrics" className="py-32 max-w-7xl mx-auto px-6 relative z-10 border-t border-white/5 bg-gradient-to-b from-transparent to-[#04060c]/50">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 text-center font-mono">
          <div className="space-y-2">
            <h4 className="text-4xl font-black text-[#25a5ff] tracking-tight">{metrics.analyzed.toLocaleString()}</h4>
            <p className="text-[10px] text-[#576575] uppercase font-black tracking-widest">Files Analyzed Cash</p>
          </div>
          <div className="space-y-2">
            <h4 className="text-4xl font-black text-red-400 tracking-tight">{metrics.detected.toLocaleString()}</h4>
            <p className="text-[10px] text-[#576575] uppercase font-black tracking-widest">Threat Signatures Discovered</p>
          </div>
          <div className="space-y-2">
            <h4 className="text-4xl font-black text-emerald-400 tracking-tight">{metrics.accuracy.toFixed(2)}%</h4>
            <p className="text-[10px] text-[#576575] uppercase font-black tracking-widest">Detection Accuracy Delta</p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-white/5 bg-[#03050a] py-12 text-center text-xs font-mono text-[#576575] relative z-10">
        <p className="tracking-widest uppercase">© 2026 BLUEINTEL PLATFORM ENGINE. ALL GLOBAL TELEMETRY SECURITY RESERVED.</p>
      </footer>
    </div>
  );
}