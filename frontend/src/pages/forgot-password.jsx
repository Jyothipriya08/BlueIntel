import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Key, AlertTriangle, CheckCircle, RefreshCw, Mail, Lock, ArrowLeft } from 'lucide-react';
import logoImg from '../assets/logo.png';

export default function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [step, setStep] = useState(1); // 1 = Request code, 2 = Verify and reset
  
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

  const navigate = useNavigate();

  const handleRequestCode = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');
    setLoading(true);

    try {
      const response = await fetch('http://127.0.0.1:8000/api/v1/auth/password-reset/request/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });

      const data = await response.json();

      if (response.ok) {
        setMessage('Password reset security token transmitted.');
        setStep(2);
      } else {
        setError(data.error || 'Password reset request failed.');
      }
    } catch (err) {
      setError('Network validation failure. Verify backend socket connectivity.');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');

    if (newPassword !== confirmPassword) {
      setError('New secret passphrases do not match.');
      return;
    }

    setLoading(true);

    try {
      const response = await fetch('http://127.0.0.1:8000/api/v1/auth/password-reset/verify/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code, new_password: newPassword })
      });

      const data = await response.json();

      if (response.ok) {
        setMessage('Passphrase updated successfully! Redirecting to login...');
        setTimeout(() => navigate('/login'), 2000);
      } else {
        setError(data.error || 'Failed to verify reset token.');
      }
    } catch (err) {
      setError('Network telemetry error resetting password.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full bg-[#01010a] flex items-center justify-center p-4 relative overflow-hidden text-white font-sans">
      <div className="absolute top-1/2 left-1/4 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-r from-[#25a5ff]/10 to-purple-500/5 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute top-1/2 right-1/4 -translate-y-1/2 w-[500px] h-[500px] bg-[#25a5ff]/5 rounded-full blur-[140px] pointer-events-none" />

      <div className="backdrop-blur-xl bg-[#0b0f19]/70 p-10 rounded-[2rem] border border-[#25a5ff]/20 w-full max-w-md shadow-[0_0_80px_rgba(37,165,255,0.08)] z-10">
        <div className="text-center mb-8">
          <div className="inline-block p-4 rounded-2xl bg-[#25a5ff]/5 border border-[#25a5ff]/10 mb-4 animate-pulse">
            <Key size={26} className="text-[#25a5ff] drop-shadow-[0_0_10px_rgba(37,165,255,0.4)]" />
          </div>
          <h1 className="text-2xl font-black tracking-wider text-white uppercase bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-200 to-[#25a5ff]">Reset Credentials</h1>
          <p className="text-xs text-[#576575] font-mono mt-2 tracking-widest uppercase font-bold">SecOps Passphrase Recovery</p>
        </div>

        {error && (
          <div className="bg-red-950/40 border border-red-500/30 text-red-400 p-4 rounded-xl text-xs flex items-center gap-3 mb-6 font-mono">
            <AlertTriangle className="h-5 w-5 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        {message && (
          <div className="bg-emerald-950/40 border border-emerald-500/30 text-emerald-400 p-4 rounded-xl text-xs flex items-center gap-3 mb-6 font-mono">
            <CheckCircle className="h-5 w-5 shrink-0 text-emerald-400" />
            <span>{message}</span>
          </div>
        )}

        {step === 1 ? (
          <form onSubmit={handleRequestCode} className="space-y-6">
            <div className="relative group">
              <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575] group-focus-within:text-[#25a5ff] transition-colors"><Mail size={16} /></span>
              <input 
                type="email" 
                value={email} 
                onChange={(e) => setEmail(e.target.value)} 
                className="w-full bg-[#04060d]/90 border border-[#25a5ff]/15 rounded-xl pl-12 pr-4 py-4 text-white text-xs font-mono focus:border-[#25a5ff] outline-none shadow-inner transition-all" 
                placeholder="REGISTERED EMAIL ADDRESS" 
                required 
              />
            </div>

            <button 
              type="submit" 
              disabled={loading}
              className="w-full bg-gradient-to-r from-[#1c212c] to-[#252f3f] border border-[#25a5ff]/30 text-white font-bold py-4 rounded-xl text-xs uppercase tracking-widest cursor-pointer hover:border-[#25a5ff] transition-all flex items-center justify-center gap-2"
            >
              {loading ? 'Transmitting Code...' : 'Request Recovery Token'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleResetPassword} className="space-y-6">
            <div className="space-y-2">
              <label className="block text-[9px] uppercase tracking-wider text-[#576575] font-mono font-bold">6-Digit Reset Token</label>
              <input 
                type="text" 
                maxLength="6"
                value={code} 
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} 
                className="w-full bg-[#04060d]/90 border border-[#25a5ff]/15 rounded-xl py-3.5 text-center text-white text-md font-mono font-bold tracking-widest focus:border-[#25a5ff] outline-none" 
                placeholder="000000" 
                required 
              />
            </div>

            <div className="relative group">
              <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575] group-focus-within:text-[#25a5ff] transition-colors"><Lock size={16} /></span>
              <input 
                type="password" 
                value={newPassword} 
                onChange={(e) => setNewPassword(e.target.value)} 
                className="w-full bg-[#04060d]/90 border border-[#25a5ff]/15 rounded-xl pl-12 pr-4 py-4 text-white text-xs font-mono focus:border-[#25a5ff] outline-none" 
                placeholder="NEW SECRET PASSPHRASE" 
                required 
              />
            </div>

            <div className="relative group">
              <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#576575] group-focus-within:text-[#25a5ff] transition-colors"><Lock size={16} /></span>
              <input 
                type="password" 
                value={confirmPassword} 
                onChange={(e) => setConfirmPassword(e.target.value)} 
                className="w-full bg-[#04060d]/90 border border-[#25a5ff]/15 rounded-xl pl-12 pr-4 py-4 text-white text-xs font-mono focus:border-[#25a5ff] outline-none" 
                placeholder="CONFIRM NEW PASSPHRASE" 
                required 
              />
            </div>

            <button 
              type="submit" 
              disabled={loading}
              className="w-full bg-gradient-to-r from-emerald-950/20 via-[#0a0f1d] to-[#25a5ff]/10 border border-[#25a5ff]/30 hover:border-[#25a5ff] text-xs py-4 rounded-xl text-white shadow-lg transition-all cursor-pointer font-bold tracking-wider flex items-center justify-center gap-3"
            >
              {loading ? 'Updating Credentials...' : 'Save New Credentials'}
            </button>
          </form>
        )}

        <div className="text-center pt-6 font-mono text-xs text-[#576575]">
          <Link to="/login" className="hover:text-white transition-colors flex items-center justify-center gap-1.5 font-bold">
            <ArrowLeft size={14} /> Back to Portal
          </Link>
        </div>
      </div>
    </div>
  );
}
