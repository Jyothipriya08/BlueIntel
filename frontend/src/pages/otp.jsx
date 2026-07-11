import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { KeyRound, AlertTriangle, ShieldAlert, CheckCircle, RefreshCw } from 'lucide-react';
import logoImg from '../assets/logo.png';

export default function OTP() {
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);
  const [timer, setTimer] = useState(60);

  const navigate = useNavigate();
  const location = useLocation();

  // Parse email from URL query or location state fallback
  const queryParams = new URLSearchParams(location.search);
  const email = queryParams.get('email') || location.state?.email || '';

  useEffect(() => {
    if (!email) {
      setError('Verification target email was not resolved. Returning to portal.');
      setTimeout(() => navigate('/login'), 3000);
    }
  }, [email, navigate]);

  useEffect(() => {
    if (timer > 0) {
      const interval = setInterval(() => setTimer(prev => prev - 1), 1000);
      return () => clearInterval(interval);
    }
  }, [timer]);

  const handleVerify = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');
    setLoading(true);

    try {
      const response = await fetch('http://127.0.0.1:8000/api/v1/auth/verify-otp/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code })
      });

      const data = await response.json();
      if (response.ok && data.token) {
        localStorage.setItem('token', data.token);
        setMessage('Identity authorized! Provisioning Security Console...');
        setTimeout(() => navigate('/dashboard'), 1500);
      } else {
        setError(data.error || 'Verification code validation failure.');
      }
    } catch (err) {
      setError('Network telemetry failure. Verify authentication nodes.');
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    if (timer > 0) return;
    setError('');
    setMessage('');
    setResending(true);

    try {
      const response = await fetch('http://127.0.0.1:8000/api/v1/auth/resend-otp/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });

      const data = await response.json();
      if (response.ok) {
        setMessage('Fresh verification code transmitted.');
        setTimer(60);
      } else {
        setError(data.error || 'OTP transmission engine failure.');
      }
    } catch (err) {
      setError('Network verification failure resending OTP.');
    } finally {
      setResending(false);
    }
  };

  return (
    <div className="min-h-screen w-full bg-[#01010a] flex items-center justify-center p-4 relative overflow-hidden text-white font-sans">
      <div className="absolute top-1/2 left-1/4 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-r from-[#25a5ff]/10 to-purple-500/5 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute top-1/2 right-1/4 -translate-y-1/2 w-[500px] h-[500px] bg-[#25a5ff]/5 rounded-full blur-[140px] pointer-events-none" />

      <div className="backdrop-blur-xl bg-[#0b0f19]/70 p-10 rounded-[2rem] border border-[#25a5ff]/20 w-full max-w-md shadow-[0_0_80px_rgba(37,165,255,0.08)] z-10">
        <div className="text-center mb-8">
          <div className="inline-block p-4 rounded-2xl bg-[#25a5ff]/5 border border-[#25a5ff]/10 mb-4 animate-pulse">
            <KeyRound size={26} className="text-[#25a5ff] drop-shadow-[0_0_10px_rgba(37,165,255,0.4)]" />
          </div>
          <h1 className="text-2xl font-black tracking-wider text-white uppercase bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-200 to-[#25a5ff]">OTP Verification</h1>
          <p className="text-xs text-[#576575] font-mono mt-2 tracking-widest uppercase font-bold">Validate Operator Identity</p>
          <p className="text-[10px] text-[#25a5ff] font-mono mt-2 truncate">Target: {email}</p>
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

        <form onSubmit={handleVerify} className="space-y-6">
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-[#576575] font-mono font-bold mb-2 text-center">6-Digit Access Token</label>
            <input 
              type="text" 
              maxLength="6"
              value={code} 
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} 
              className="w-full bg-[#04060d]/90 border border-[#25a5ff]/20 rounded-xl py-4 text-center text-white text-lg font-mono font-bold tracking-[0.5em] focus:border-[#25a5ff] outline-none shadow-inner" 
              placeholder="000000" 
              required 
            />
          </div>

          <button 
            type="submit" 
            disabled={loading || code.length !== 6}
            className="w-full bg-gradient-to-r from-[#1c212c] to-[#252f3f] border border-[#25a5ff]/30 text-white font-bold py-4 rounded-xl text-xs uppercase tracking-widest cursor-pointer hover:border-[#25a5ff] shadow-[0_4px_20px_rgba(0,0,0,0.4)] hover:shadow-[#25a5ff]/10 transition-all flex items-center justify-center gap-2"
          >
            {loading ? 'Authorizing Code...' : 'Submit Verification Node'}
          </button>
        </form>

        <div className="text-center pt-6 font-mono text-xs text-[#576575]">
          Didn't receive verified code?{' '}
          <button 
            onClick={handleResend}
            disabled={timer > 0 || resending}
            className={`font-bold transition-colors ${timer > 0 ? 'text-[#576575]' : 'text-[#25a5ff] hover:underline cursor-pointer'}`}
          >
            {resending ? 'Transmitting...' : timer > 0 ? `Resend in ${timer}s` : 'Resend OTP'}
          </button>
        </div>
      </div>
    </div>
  );
}
