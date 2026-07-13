import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Settings as SettingsIcon, Shield, Key, Eye, EyeOff, Save, ArrowLeft, CheckCircle2, AlertCircle } from 'lucide-react';

export default function Settings() {
  const [theme, setTheme] = useState('dark');
  const [enableNotifications, setEnableNotifications] = useState(true);
  const [vtKey, setVtKey] = useState('');
  const [claudeKey, setClaudeKey] = useState('');
  
  const [vtConfigured, setVtConfigured] = useState(false);
  const [claudeConfigured, setClaudeConfigured] = useState(false);

  const [showVt, setShowVt] = useState(false);
  const [showClaude, setShowClaude] = useState(false);

  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

  const navigate = useNavigate();
  const token = localStorage.getItem('token');
  const API_BASE = `http://${window.location.hostname}:8000`;

  useEffect(() => {
    const fetchSettings = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/v1/settings/`);
        if (response.ok) {
          const data = await response.json();
          setTheme(data.theme);
          setEnableNotifications(data.enable_notifications);
          setVtConfigured(data.vt_key_configured);
          setClaudeConfigured(data.claude_key_configured);
        } else {
          setError('Failed to fetch settings from backend registries.');
        }
      } catch (err) {
        setError('Network telemetry failure connecting to server settings.');
      }
    };
    fetchSettings();
  }, [API_BASE]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');
    setLoading(true);

    const payload = {
      theme,
      enable_notifications: enableNotifications,
    };
    if (vtKey.trim()) payload.vt_key = vtKey;
    if (claudeKey.trim()) payload.claude_key = claudeKey;

    try {
      const response = await fetch(`${API_BASE}/api/v1/settings/`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      const data = await response.json();
      if (response.ok) {
        setMessage('Operator settings catalog updated successfully.');
        setVtConfigured(data.vt_key_configured);
        setClaudeConfigured(data.claude_key_configured);
        setVtKey('');
        setClaudeKey('');
      } else {
        setError(data.error || 'Failed to update preferences matrix.');
      }
    } catch (err) {
      setError('Network validation failure syncing settings.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full bg-[#02020a] text-white font-sans selection:bg-[#25a5ff]/30 selection:text-white p-6 md:p-12 relative overflow-hidden">
      <div className="absolute top-1/2 left-1/4 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-r from-[#25a5ff]/10 to-purple-500/5 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute top-1/2 right-1/4 -translate-y-1/2 w-[500px] h-[500px] bg-[#25a5ff]/5 rounded-full blur-[140px] pointer-events-none" />

      <div className="max-w-3xl mx-auto backdrop-blur-xl bg-[#0b0f19]/70 border border-[#25a5ff]/15 rounded-[2.5rem] p-8 md:p-12 shadow-2xl relative z-10">
        <header className="flex justify-between items-center border-b border-[#25a5ff]/10 pb-6 mb-8">
          <div className="flex items-center space-x-4">
            <div className="p-3 bg-[#25a5ff]/5 border border-[#25a5ff]/20 rounded-2xl text-[#25a5ff] animate-pulse">
              <SettingsIcon size={24} />
            </div>
            <div>
              <h1 className="text-2xl font-black uppercase tracking-wider">Console Config</h1>
              <p className="text-[10px] text-[#576575] font-mono uppercase tracking-widest font-black">Operator Telemetry Settings</p>
            </div>
          </div>
          <button 
            onClick={() => navigate('/dashboard')} 
            className="px-4 py-2.5 bg-[#0a0f1d] border border-white/5 hover:border-[#25a5ff]/30 text-xs font-mono font-bold uppercase rounded-xl flex items-center gap-2 transition-all cursor-pointer text-gray-400 hover:text-white"
          >
            <ArrowLeft size={14} /> Back to Grid
          </button>
        </header>

        {error && (
          <div className="bg-red-950/40 border border-red-500/30 text-red-400 p-4 rounded-2xl text-xs flex items-center gap-3 mb-6 font-mono">
            <AlertCircle className="h-5 w-5 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        {message && (
          <div className="bg-emerald-950/40 border border-emerald-500/30 text-emerald-400 p-4 rounded-2xl text-xs flex items-center gap-3 mb-6 font-mono">
            <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-400" />
            <span>{message}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-8">
          {/* Key Configurations */}
          <div className="space-y-6">
            <h3 className="text-xs font-mono font-black text-[#25a5ff] uppercase tracking-widest border-b border-[#25a5ff]/10 pb-2">Cryptography Keys Store</h3>
            
            {/* VirusTotal Key Input */}
            <div className="space-y-2">
              <div className="flex justify-between items-center text-xs">
                <label className="font-mono uppercase text-gray-400 font-bold flex items-center gap-1"><Key size={14}/> VirusTotal API Key</label>
                <span className={`text-[9px] font-mono px-2 py-0.5 rounded ${vtConfigured ? 'bg-emerald-500/10 text-emerald-400' : 'bg-yellow-500/10 text-yellow-400'}`}>
                  {vtConfigured ? '🟢 KEY CONFIGURED' : '🟡 UNCONFIGURED'}
                </span>
              </div>
              <div className="relative">
                <input 
                  type={showVt ? "text" : "password"} 
                  value={vtKey}
                  onChange={(e) => setVtKey(e.target.value)}
                  className="w-full bg-[#04060d]/90 border border-white/10 focus:border-[#25a5ff] rounded-xl px-4 py-3.5 text-xs text-white font-mono outline-none transition-all shadow-inner"
                  placeholder={vtConfigured ? "Type to overwrite existing VirusTotal key..." : "Enter VirusTotal V3 API Credentials..."}
                />
                <button 
                  type="button"
                  onClick={() => setShowVt(!showVt)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                >
                  {showVt ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* Claude API Key Input */}
            <div className="space-y-2">
              <div className="flex justify-between items-center text-xs">
                <label className="font-mono uppercase text-gray-400 font-bold flex items-center gap-1"><Key size={14}/> Anthropic Claude API Key</label>
                <span className={`text-[9px] font-mono px-2 py-0.5 rounded ${claudeConfigured ? 'bg-emerald-500/10 text-emerald-400' : 'bg-yellow-500/10 text-yellow-400'}`}>
                  {claudeConfigured ? '🟢 KEY CONFIGURED' : '🟡 UNCONFIGURED'}
                </span>
              </div>
              <div className="relative">
                <input 
                  type={showClaude ? "text" : "password"} 
                  value={claudeKey}
                  onChange={(e) => setClaudeKey(e.target.value)}
                  className="w-full bg-[#04060d]/90 border border-white/10 focus:border-[#25a5ff] rounded-xl px-4 py-3.5 text-xs text-white font-mono outline-none transition-all shadow-inner"
                  placeholder={claudeConfigured ? "Type to overwrite existing Claude key..." : "Enter Anthropic API Credentials..."}
                />
                <button 
                  type="button"
                  onClick={() => setShowClaude(!showClaude)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                >
                  {showClaude ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>
          </div>

          {/* Preferences */}
          <div className="space-y-6">
            <h3 className="text-xs font-mono font-black text-[#25a5ff] uppercase tracking-widest border-b border-[#25a5ff]/10 pb-2">User Interface Preferences</h3>
            
            <div className="flex items-center justify-between py-2 text-xs">
              <div>
                <p className="font-mono uppercase text-gray-200 font-bold">Theme Settings</p>
                <p className="text-[10px] text-gray-400">Select active console dashboard layout theme.</p>
              </div>
              <select 
                value={theme}
                onChange={(e) => setTheme(e.target.value)}
                className="bg-[#0b101c] border border-white/10 rounded-xl px-4 py-2.5 text-xs text-white focus:outline-none focus:border-[#25a5ff]"
              >
                <option value="dark">Secure Dark Mode</option>
                <option value="cyberpunk">Cyber Matrix (Blue/Red)</option>
              </select>
            </div>

            <div className="flex items-center justify-between py-2 text-xs">
              <div>
                <p className="font-mono uppercase text-gray-200 font-bold">Heuristic Notifications</p>
                <p className="text-[10px] text-gray-400">Enable instant warning logs for malicious ingests.</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={enableNotifications} 
                  onChange={(e) => setEnableNotifications(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-gray-300 after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-[#25a5ff]" />
              </label>
            </div>
          </div>

          {/* Submit Trigger */}
          <button 
            type="submit" 
            disabled={loading}
            className="w-full py-4 bg-gradient-to-r from-[#1e3a8a] to-[#25a5ff] text-white font-mono font-bold uppercase text-xs rounded-xl shadow-[0_4px_20px_rgba(37,165,255,0.2)] hover:scale-[1.01] active:scale-[0.99] transition-all flex items-center justify-center gap-2 cursor-pointer border border-[#25a5ff]/20"
          >
            <Save size={16} /> {loading ? 'Synchronizing configuration...' : 'Commit Configurations'}
          </button>
        </form>
      </div>
    </div>
  );
}
