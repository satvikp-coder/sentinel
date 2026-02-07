
import React from 'react';
import { Shield, Lock } from 'lucide-react';

const AuthLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <div className="min-h-screen bg-[#020617] flex flex-col items-center justify-center p-4 relative overflow-hidden">
      {/* Background Elements */}
      <div className="absolute inset-0 z-0 opacity-20 pointer-events-none" 
        style={{
          backgroundImage: `linear-gradient(rgba(99, 102, 241, 0.05) 1px, transparent 1px),
          linear-gradient(90deg, rgba(99, 102, 241, 0.05) 1px, transparent 1px)`,
          backgroundSize: '40px 40px',
        }}
      ></div>
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-indigo-600/10 rounded-full blur-[100px] pointer-events-none"></div>

      <div className="w-full max-w-md z-10">
        <div className="flex flex-col items-center mb-10">
          <div className="w-16 h-16 bg-indigo-500/10 rounded-2xl flex items-center justify-center text-indigo-400 border border-indigo-500/20 shadow-[0_0_30px_rgba(99,102,241,0.2)] mb-6 animate-pulse">
             <Shield size={32} strokeWidth={2} />
          </div>
          <h1 className="text-3xl font-black text-white uppercase tracking-tighter">Sentinel</h1>
          <p className="text-[10px] font-black uppercase tracking-[0.3em] text-slate-500 mt-2">Secure Agent Platform</p>
        </div>
        {children}
      </div>
      
      {/* Upgraded Footer */}
      <div className="mt-12 flex items-center gap-3 px-5 py-2.5 rounded-full bg-slate-900/80 border border-white/5 backdrop-blur-md shadow-2xl">
        <div className="relative flex items-center justify-center">
           <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_10px_#10b981] animate-pulse"></div>
           <div className="absolute inset-0 w-2 h-2 rounded-full bg-emerald-500/50 animate-ping"></div>
        </div>
        <div className="h-4 w-px bg-white/10"></div>
        <div className="flex items-center gap-2">
          <Lock size={10} className="text-slate-400" />
          <span className="text-[10px] font-mono font-bold text-slate-300 tracking-[0.15em] uppercase">
            Secure Connection <span className="text-slate-600 mx-1">//</span> Encrypted
          </span>
        </div>
      </div>
    </div>
  );
};

export default AuthLayout;
