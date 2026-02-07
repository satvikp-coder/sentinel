
import React, { useState, useMemo } from 'react';
import Layout from './components/Layout';
import AuthLayout from './components/AuthLayout';
import Dashboard from './pages/Dashboard';
import SessionDetail from './pages/SessionDetail';
import DemoMode from './pages/DemoMode';
import Evaluation from './pages/Evaluation';
import AuditLog from './pages/AuditLog';
import PolicySandbox from './pages/PolicySandbox';
import SplashScreen from './components/SplashScreen';
import SafetyPledgeModal from './components/SafetyPledgeModal';
import { ToastProvider } from './components/Toast';
import { Shield, ArrowRight, ChevronLeft, Check, X } from 'lucide-react';

type AuthState = 'LOGIN' | 'SIGNUP' | 'OTP' | 'APP';

// Password validation helper
const validatePassword = (password: string) => ({
  minLength: password.length >= 8,
  hasUppercase: /[A-Z]/.test(password),
  hasLowercase: /[a-z]/.test(password),
  hasNumber: /[0-9]/.test(password),
  hasSpecial: /[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/`~;']/.test(password),
});

const App: React.FC = () => {
  const [showSplash, setShowSplash] = useState(true);
  const [authState, setAuthState] = useState<AuthState>('LOGIN');
  const [showPledge, setShowPledge] = useState(false);

  // Routing State
  const [currentPage, setCurrentPage] = useState<string>('dashboard');
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);

  // Form States
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [role, setRole] = useState('OPERATOR');
  const [otp, setOtp] = useState('');
  const [loginError, setLoginError] = useState<string | null>(null);
  const [signupError, setSignupError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // Password validation
  const passwordValidation = useMemo(() => validatePassword(password), [password]);
  const isPasswordValid = Object.values(passwordValidation).every(Boolean);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);
    setIsLoading(true);

    try {
      const response = await fetch('http://localhost:8000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: loginPassword })
      });

      if (!response.ok) {
        const data = await response.json();
        setLoginError(data.detail || 'Login failed');
        return;
      }

      setAuthState('OTP');
    } catch (error) {
      setLoginError('Connection error. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    setSignupError(null);

    if (!isPasswordValid) {
      setSignupError('Please ensure your password meets all requirements.');
      return;
    }

    setIsLoading(true);

    try {
      const response = await fetch('http://localhost:8000/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, role })
      });

      if (!response.ok) {
        const data = await response.json();
        setSignupError(data.detail || 'Signup failed');
        return;
      }

      setAuthState('OTP');
    } catch (error) {
      setSignupError('Connection error. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const [otpError, setOtpError] = useState<string | null>(null);

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setOtpError(null);
    setIsLoading(true);

    try {
      const response = await fetch('http://localhost:8000/api/auth/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp })
      });

      if (!response.ok) {
        const data = await response.json();
        setOtpError(data.detail || 'Invalid OTP. Please try again.');
        return;
      }

      setAuthState('APP');
      setShowPledge(true);
    } catch (error) {
      setOtpError('Connection error. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePledgeConfirm = () => {
    setShowPledge(false);
  };

  const handleLogout = () => {
    setAuthState('LOGIN');
    setEmail('');
    setOtp('');
    setShowPledge(false);
  };

  const handleNavigate = (page: string) => {
    setCurrentPage(page);
    setSelectedSessionId(null);
  };

  const handleSessionSelect = (id: string) => {
    setSelectedSessionId(id);
    setCurrentPage('session-detail');
  };

  const renderAppContent = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard onSessionSelect={handleSessionSelect} />;
      case 'session-detail':
        return selectedSessionId
          ? <SessionDetail sessionId={selectedSessionId} onBack={() => handleNavigate('dashboard')} />
          : <Dashboard onSessionSelect={handleSessionSelect} />;
      case 'demo':
        return <DemoMode />;
      case 'evaluation':
        return <Evaluation />;
      case 'audit':
        return <AuditLog />;
      case 'policy':
        return <PolicySandbox />;
      default:
        return <Dashboard onSessionSelect={handleSessionSelect} />;
    }
  };

  if (showSplash) {
    return <SplashScreen onComplete={() => setShowSplash(false)} />;
  }

  // Authentication Flow
  if (authState !== 'APP') {
    return (
      <AuthLayout>
        {authState === 'LOGIN' && (
          <form onSubmit={handleLogin} className="space-y-6 bg-slate-900 p-8 rounded-3xl border border-white/10 shadow-2xl animate-in fade-in slide-in-from-bottom-4 duration-500">
            <h2 className="text-xl font-black text-white uppercase tracking-tight text-center mb-6">Operator Login</h2>

            {/* Dynamic Error Message */}
            {loginError && (
              <div className="bg-rose-500/10 border border-rose-500/30 rounded-xl px-4 py-3">
                <p className="text-xs text-rose-400 text-center">
                  <span className="font-bold">{loginError}</span>
                  {loginError.includes('not registered') && (
                    <>
                      {' '}
                      <button
                        type="button"
                        onClick={() => { setAuthState('SIGNUP'); setLoginError(null); }}
                        className="underline hover:text-rose-300 transition-colors font-bold"
                      >
                        Create an account here
                      </button>
                    </>
                  )}
                </p>
              </div>
            )}

            <div className="space-y-2">
              <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Email Access ID</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-black border border-white/10 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-indigo-500 transition-colors"
                placeholder="operator@sentinel.gov"
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Secure Password</label>
              <input
                type="password"
                required
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
                className="w-full bg-black border border-white/10 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-indigo-500 transition-colors"
                placeholder="••••••••••••"
              />
            </div>
            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-800 disabled:cursor-not-allowed text-white py-3 rounded-xl font-bold uppercase tracking-wider text-xs shadow-[0_0_20px_rgba(99,102,241,0.3)] transition-all"
            >
              {isLoading ? 'Authenticating...' : 'Initiate Handshake'}
            </button>

            <div className="pt-2">
              <button
                type="button"
                className="w-full group flex items-center justify-center gap-2 text-xs font-bold uppercase tracking-widest text-slate-500 hover:text-white transition-all duration-300"
                onClick={() => { setAuthState('SIGNUP'); setLoginError(null); }}
              >
                <span>Request New Clearance</span>
                <ArrowRight size={14} className="text-indigo-500 group-hover:translate-x-1 transition-transform" />
              </button>
            </div>
          </form>
        )}

        {authState === 'SIGNUP' && (
          <form onSubmit={handleSignup} className="space-y-6 bg-slate-900 p-8 rounded-3xl border border-white/10 shadow-2xl animate-in fade-in slide-in-from-bottom-4 duration-500">
            <h2 className="text-xl font-black text-white uppercase tracking-tight text-center mb-6">New Clearance Request</h2>

            {/* Signup Error Message */}
            {signupError && (
              <div className="bg-rose-500/10 border border-rose-500/30 rounded-xl px-4 py-3">
                <p className="text-xs text-rose-400 text-center font-bold">{signupError}</p>
              </div>
            )}

            <div className="space-y-2">
              <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Email Access ID</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-black border border-white/10 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-indigo-500 transition-colors"
                placeholder="researcher@sentinel.gov"
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Role Assignment</label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="w-full bg-black border border-white/10 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-indigo-500 transition-colors"
              >
                <option value="OPERATOR">Human Operator</option>
                <option value="RESEARCHER">Security Researcher</option>
                <option value="ADMIN">System Administrator</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Set Password</label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={`w-full bg-black border rounded-xl px-4 py-3 text-sm text-white focus:outline-none transition-colors ${password.length > 0
                  ? isPasswordValid
                    ? 'border-emerald-500 focus:border-emerald-400'
                    : 'border-rose-500 focus:border-rose-400'
                  : 'border-white/10 focus:border-indigo-500'
                  }`}
                placeholder="••••••••••••"
              />

              {/* Password Requirements */}
              {password.length > 0 && (
                <div className="mt-3 p-3 bg-black/50 rounded-xl border border-white/5">
                  <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2">Password Requirements</p>
                  <div className="grid grid-cols-1 gap-1.5">
                    <div className={`flex items-center gap-2 text-xs ${passwordValidation.minLength ? 'text-emerald-400' : 'text-slate-500'}`}>
                      {passwordValidation.minLength ? <Check size={12} /> : <X size={12} />}
                      <span>Minimum 8 characters</span>
                    </div>
                    <div className={`flex items-center gap-2 text-xs ${passwordValidation.hasUppercase ? 'text-emerald-400' : 'text-slate-500'}`}>
                      {passwordValidation.hasUppercase ? <Check size={12} /> : <X size={12} />}
                      <span>At least one uppercase letter (A-Z)</span>
                    </div>
                    <div className={`flex items-center gap-2 text-xs ${passwordValidation.hasLowercase ? 'text-emerald-400' : 'text-slate-500'}`}>
                      {passwordValidation.hasLowercase ? <Check size={12} /> : <X size={12} />}
                      <span>At least one lowercase letter (a-z)</span>
                    </div>
                    <div className={`flex items-center gap-2 text-xs ${passwordValidation.hasNumber ? 'text-emerald-400' : 'text-slate-500'}`}>
                      {passwordValidation.hasNumber ? <Check size={12} /> : <X size={12} />}
                      <span>At least one number (0-9)</span>
                    </div>
                    <div className={`flex items-center gap-2 text-xs ${passwordValidation.hasSpecial ? 'text-emerald-400' : 'text-slate-500'}`}>
                      {passwordValidation.hasSpecial ? <Check size={12} /> : <X size={12} />}
                      <span>At least one special character (!@#$%^&*)</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
            <button type="submit" className="w-full bg-indigo-600 hover:bg-indigo-500 text-white py-3 rounded-xl font-bold uppercase tracking-wider text-xs shadow-[0_0_20px_rgba(99,102,241,0.3)] transition-all">
              Submit Request
            </button>

            <div className="pt-2">
              <button
                type="button"
                className="w-full group flex items-center justify-center gap-2 text-xs font-bold uppercase tracking-widest text-slate-500 hover:text-white transition-all duration-300"
                onClick={() => setAuthState('LOGIN')}
              >
                <ChevronLeft size={14} className="text-indigo-500 group-hover:-translate-x-1 transition-transform" />
                <span>Return to Login</span>
              </button>
            </div>
          </form>
        )}

        {authState === 'OTP' && (
          <form onSubmit={handleVerifyOtp} className="space-y-6 bg-slate-900 p-8 rounded-3xl border border-white/10 shadow-2xl animate-in fade-in slide-in-from-bottom-4 duration-500 w-full max-w-sm">
            <div className="text-center mb-6">
              <Shield size={48} className="mx-auto text-emerald-500 mb-4 animate-pulse" />
              <h2 className="text-xl font-black text-white uppercase tracking-tight">2FA Verification</h2>
              <p className="text-xs text-slate-400 mt-2 font-mono">Enter the 6-digit token sent to your email.</p>
            </div>

            {/* OTP Error Message */}
            {otpError && (
              <div className="bg-rose-500/10 border border-rose-500/30 rounded-xl px-4 py-3">
                <p className="text-xs text-rose-400 text-center font-bold">{otpError}</p>
              </div>
            )}

            <div className="flex justify-center gap-2">
              <input
                type="text"
                placeholder="000000"
                maxLength={6}
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
                className="w-full text-center bg-black border border-white/10 rounded-xl px-4 py-4 text-2xl font-mono text-white tracking-[0.5em] focus:outline-none focus:border-emerald-500 transition-colors"
              />
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-800 disabled:cursor-not-allowed text-white py-3 rounded-xl font-bold uppercase tracking-wider text-xs shadow-[0_0_20px_rgba(16,185,129,0.3)] transition-all"
            >
              {isLoading ? 'Verifying...' : 'Verify Identity'}
            </button>

            <div className="pt-2">
              <button
                type="button"
                className="w-full group flex items-center justify-center gap-2 text-xs font-bold uppercase tracking-widest text-slate-500 hover:text-rose-400 transition-all duration-300"
                onClick={() => setAuthState('LOGIN')}
              >
                <span>Abort Authentication</span>
              </button>
            </div>
          </form>
        )}
      </AuthLayout>
    );
  }

  return (
    <ToastProvider>
      <Layout activePage={currentPage} onNavigate={handleNavigate} onLogout={handleLogout}>
        {showPledge && <SafetyPledgeModal onConfirm={handlePledgeConfirm} />}
        <div className="animate-in fade-in slide-in-from-bottom-4 duration-700 ease-out h-full">
          {renderAppContent()}
        </div>
      </Layout>
    </ToastProvider>
  );
};

export default App;
