import React, { useState, useEffect } from 'react';
import { useNavigate, Link, useLocation } from 'react-router-dom';
import { Eye, EyeOff, AlertTriangle, Terminal, Mail, Lock, Radio } from 'lucide-react';
import logoImg from '../assets/logo.png';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const navigate = useNavigate();
  const location = useLocation();

  // Handle callback triggers from Google SSO redirections
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const token = params.get('token');
    const errorParam = params.get('error');
    const authSuccess = params.get('auth');

    if (token) {
      localStorage.setItem('token', token);
      navigate('/dashboard');
    } else if (authSuccess === 'success') {
      const fetchSessionToken = async () => {
        setLoading(true);
        try {
          const response = await fetch('http://127.0.0.1:8000/api/v1/auth/session-token/', {
            credentials: 'include'
          });
          const data = await response.json();
          if (response.ok && data.token) {
            localStorage.setItem('token', data.token);
            navigate('/dashboard');
          } else {
            setError(data.error || 'Failed to authenticate Google session token.');
          }
        } catch (err) {
          setError('Network failure validating Google session credentials.');
        } finally {
          setLoading(false);
        }
      };
      fetchSessionToken();
    } else if (errorParam) {
      setError(decodeURIComponent(errorParam));
    }
  }, [location, navigate]);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch('http://127.0.0.1:8000/api/v1/auth/login/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      
      const data = await response.json();

      if (response.ok && data.token) {
        localStorage.setItem('token', data.token);
        navigate('/dashboard');
      } else if (response.status === 403 && data.status === 'verification_pending') {
        // Redirect operator to verify their OTP code
        navigate(`/otp?email=${encodeURIComponent(email)}`, { state: { email } });
      } else {
        setError(data.error || 'Invalid Identity Credentials Provided');
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
          <h1 className="text-3xl font-black tracking-wider text-white uppercase bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-200 to-[#25a5ff]">BlueIntel Console</h1>
          <p className="text-xs text-[#576575] font-mono mt-2 tracking-widest uppercase font-bold">SecOps Authorization Gateway</p>
        </div>

        {error && (
          <div className="bg-red-950/40 border border-red-500/30 text-red-400 p-4 rounded-xl text-xs flex items-center gap-3 mb-6 font-mono">
            <AlertTriangle className="h-5 w-5 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-6">
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

          <button 
            type="submit" 
            disabled={loading}
            className="w-full bg-gradient-to-r from-[#1c212c] to-[#252f3f] border border-[#25a5ff]/30 text-white font-bold py-4 rounded-xl text-xs uppercase tracking-widest cursor-pointer hover:border-[#25a5ff] shadow-[0_4px_20px_rgba(0,0,0,0.4)] hover:shadow-[#25a5ff]/10 transition-all flex items-center justify-center gap-2"
          >
            <Terminal size={16} className="text-[#25a5ff]" /> 
            {loading ? 'Verifying Identity...' : 'Local Terminal Access'}
          </button>

          <div className="relative flex py-2 items-center">
            <div className="flex-grow border-t border-white/5"></div>
            <span className="flex-shrink mx-4 text-[9px] font-mono tracking-widest text-[#576575] uppercase">OR</span>
            <div className="flex-grow border-t border-white/5"></div>
          </div>

          <button 
            type="button" 
            onClick={() => window.location.href = 'http://127.0.0.1:8000/api/v1/auth/google/login/'}
            className="w-full bg-gradient-to-r from-purple-950/20 via-[#0a0f1d] to-[#25a5ff]/10 border border-[#25a5ff]/30 hover:border-[#25a5ff] text-xs py-4 rounded-xl text-white shadow-lg transition-all cursor-pointer font-bold tracking-wider flex items-center justify-center gap-3"
          >
            <Radio size={16} className="text-[#25a5ff] animate-pulse" /> Google Provider SSO Login
          </button>

          <p className="text-center text-xs text-[#576575] pt-4 font-mono flex justify-between px-2">
            <Link to="/forgot-password" className="text-[#25a5ff] hover:underline">Forgot Password?</Link>
            <span>
              New operator? <Link to="/signup" className="text-[#25a5ff] font-bold hover:underline">Sign up</Link>
            </span>
          </p>
        </form>
      </div>
    </div>
  );
}