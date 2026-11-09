
import React from 'react';
import { User, ShieldCheck, Bot, Globe, ArrowRight } from 'lucide-react';

const SystemFlowVisual: React.FC = () => {
  return (
    <div className="w-full bg-slate-900 border border-white/5 rounded-3xl p-6 mb-8 relative overflow-hidden group">
      <div className="absolute inset-0 bg-indigo-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-700"></div>
      
      <div className="flex flex-col md:flex-row items-center justify-between gap-4 relative z-10">
        
        {/* Human */}
        <div className="flex flex-col items-center space-y-2">
          <div className="w-12 h-12 bg-slate-800 rounded-full flex items-center justify-center border border-white/10 shadow-lg">
            <User size={20} className="text-slate-400" />
          </div>
          <span className="text-[10px] font-black uppercase tracking-widest text-slate-500">Human Operator</span>
        </div>

        {/* Arrow */}
        <div className="h-px w-full md:w-auto md:flex-1 bg-slate-800 relative">
          <div className="absolute inset-0 bg-indigo-500/50 w-1/2 animate-[shimmer_2s_infinite]"></div>
        </div>

        {/* Security Layer (Highlighted) */}
        <div className="flex flex-col items-center space-y-2 relative">
           <div className="absolute -inset-4 bg-indigo-500/10 rounded-full blur-xl animate-pulse"></div>
           <div className="w-16 h-16 bg-indigo-600 rounded-2xl flex items-center justify-center border border-indigo-400 shadow-[0_0_20px_rgba(99,102,241,0.4)] relative z-10">
             <ShieldCheck size={32} className="text-white" />
           </div>
           <span className="text-xs font-black uppercase tracking-widest text-indigo-400">Security Layer</span>
        </div>

        {/* Arrow */}
        <div className="h-px w-full md:w-auto md:flex-1 bg-slate-800"></div>

        {/* Agent */}
        <div className="flex flex-col items-center space-y-2">
          <div className="w-12 h-12 bg-slate-800 rounded-full flex items-center justify-center border border-white/10 shadow-lg">
            <Bot size={20} className="text-emerald-400" />
          </div>
          <span className="text-[10px] font-black uppercase tracking-widest text-slate-500">Agentic Browser</span>
        </div>

        {/* Arrow */}
        <div className="h-px w-full md:w-auto md:flex-1 bg-slate-800"></div>

        {/* Web */}
        <div className="flex flex-col items-center space-y-2">
          <div className="w-12 h-12 bg-slate-800 rounded-full flex items-center justify-center border border-white/10 shadow-lg">
            <Globe size={20} className="text-rose-400" />
          </div>
          <span className="text-[10px] font-black uppercase tracking-widest text-slate-500">Untrusted Web</span>
        </div>

      </div>
      
      <div className="absolute top-2 right-4 flex items-center space-x-2">
        <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></div>
        <span className="text-[10px] font-mono text-emerald-500">ACTIVE MEDIATION</span>
      </div>
    </div>
  );
};

export default SystemFlowVisual;
