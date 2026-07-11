import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Eye, EyeOff, AlertTriangle, ShieldCheck, Mail, Lock, User } from 'lucide-react';
import logoImg from '../assets/logo.png';

export default function Signup() {
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSignup = async (e) => {
    e.preventDefault();
    setError('');

    if (password !== confirmPassword) {
      setError('Secret passphrases do not match.');
      return;
    }

    setLoading(true);

    try {
      const response = await fetch('http://127.0.0.1:8000/api/v1/auth/signup/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, username, password })
      });
      
      const data = await response.json();

      if (response.ok && data.token) {
        localStorage.setItem('token', data.token);
        navigate('/dashboard');
      } else {
        setError(data.error || 'Identity registration matrix failed.');
      }
    } catch (err) {
      setError('Network validation failure. Verify authentication node connectivity.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full bg-[#01010a] flex items-center justify-center p-4 relative overflow-hidden text-white font-sans">
      <div className="absolute top-1/2 left-1/4 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-r from-[#25a5ff]/10 to-purple-500/5 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute top-1/2 right-1/4 -translate-y-1/2 w-[500px] h-[500px] bg-[#25a5ff]/5 rounded-full blur-[140px] pointer-events-none" />

      <div className="backdrop-blur-xl bg-[#0b0f19]/70 p-10 rounded-[2rem] border border-[#25a5ff]/20 w-full max-w-lg shadow-[0_0_80px_rgba(37,165,255,0.08)] z-10">
        <div className="text-center mb-8">
          <div className="inline-block p-4 rounded-2xl bg-[#25a5ff]/5 border border-[#25a5ff]/10 mb-4 animate-pulse">
            <img src={logoImg} alt="BlueIntel Logo" className="w-14 h-14 object-contain drop-shadow-[0_0_15px_rgba(37,165,255,0.3)]" />
          </div>
          <h1 className="text-3xl font-black tracking-wider text-white uppercase bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-200 to-[#25a5ff]">BlueIntel Onboarding</h1>
          <p className="text-xs text-[#576575] font-mono mt-2 tracking-widest uppercase font-bold">Register Operator Credentials</p>
        </div>

        {error && (
          <div className="bg-red-950/40 border border-red-500/30 text-red-400 p-4 rounded-xl text-xs flex items-center gap-3 mb-6 font-mono">
            <AlertTriangle className="h-5 w-5 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSignup} className="space-y-4">
          <div className="relative group">
            <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575] group-focus-within:text-[#25a5ff] transition-colors"><Mail size={16} /></span>
            <input 
              type="email" 
              value={email} 
              onChange={(e) => setEmail(e.target.value)} 
              className="w-full bg-[#04060d]/90 border border-[#25a5ff]/15 rounded-xl pl-12 pr-4 py-4 text-white text-xs font-mono focus:border-[#25a5ff] outline-none shadow-inner transition-all" 
              placeholder="OPERATOR EMAIL ADDRESS" 
              required 
            />
          </div>

          <div className="relative group">
            <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575] group-focus-within:text-[#25a5ff] transition-colors"><User size={16} /></span>
            <input 
              type="text" 
              value={username} 
              onChange={(e) => setUsername(e.target.value)} 
              className="w-full bg-[#04060d]/90 border border-[#25a5ff]/15 rounded-xl pl-12 pr-4 py-4 text-white text-xs font-mono focus:border-[#25a5ff] outline-none shadow-inner transition-all" 
              placeholder="OPERATOR CALLSIGN (USERNAME)" 
              required 
            />
          </div>

          <div className="relative group">
            <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575] group-focus-within:text-[#25a5ff] transition-colors"><Lock size={16} /></span>
            <input 
              type={showPassword ? "text" : "password"} 
              value={password} 
              onChange={(e) => setPassword(e.target.value)} 
              className="w-full bg-[#04060d]/90 border border-[#25a5ff]/15 rounded-xl pl-12 pr-12 py-4 text-white text-xs font-mono focus:border-[#25a5ff] outline-none shadow-inner transition-all" 
              placeholder="SECRET PASSPHRASE" 
              required 
            />
            <button 
              type="button" 
              onClick={() => setShowPassword(!showPassword)} 
              className="absolute right-4 top-1/2 -translate-y-1/2 text-[#576575] hover:text-[#25a5ff]"
            >
              {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>

          <div className="relative group">
            <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575] group-focus-within:text-[#25a5ff] transition-colors"><Lock size={16} /></span>
            <input 
              type={showPassword ? "text" : "password"} 
              value={confirmPassword} 
              onChange={(e) => setConfirmPassword(e.target.value)} 
              className="w-full bg-[#04060d]/90 border border-[#25a5ff]/15 rounded-xl pl-12 pr-4 py-4 text-white text-xs font-mono focus:border-[#25a5ff] outline-none shadow-inner transition-all" 
              placeholder="CONFIRM SECURE PASSPHRASE" 
              required 
            />
          </div>

          <button 
            type="submit" 
            disabled={loading}
            className="w-full bg-gradient-to-r from-[#1c212c] to-[#252f3f] border border-[#25a5ff]/30 text-white font-bold py-4 rounded-xl text-xs uppercase tracking-widest cursor-pointer hover:border-[#25a5ff] shadow-[0_4px_20px_rgba(0,0,0,0.4)] hover:shadow-[#25a5ff]/10 transition-all flex items-center justify-center gap-2"
          >
            <ShieldCheck size={16} className="text-[#25a5ff]" /> 
            {loading ? 'Initializing Operator Node...' : 'Register Access Node'}
          </button>

          <p className="text-center text-xs text-[#576575] pt-4 font-mono">
            Already authorized callsign? <Link to="/login" className="text-[#25a5ff] font-bold hover:underline">Log in</Link>
          </p>
        </form>
      </div>
    </div>
  );
}
