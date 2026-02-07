
import React from 'react';
import { SemanticAnalysis } from '../types';
import { Brain, ArrowRight, AlertTriangle, CheckCircle, Split } from 'lucide-react';

interface SemanticFirewallProps {
  analysis?: SemanticAnalysis;
}

const SemanticFirewall: React.FC<SemanticFirewallProps> = ({ analysis }) => {
  if (!analysis) return null;

  const isDivergent = analysis.divergenceScore > 50;
  const color = isDivergent ? 'text-rose-500' : 'text-emerald-500';
  const bg = isDivergent ? 'bg-rose-500/10' : 'bg-emerald-500/10';
  const border = isDivergent ? 'border-rose-500/20' : 'border-emerald-500/20';

  return (
    <div className="bg-slate-900 border border-white/5 rounded-3xl p-6 shadow-xl relative overflow-hidden">
      <div className="flex items-center gap-2 mb-6">
        <Brain size={18} className="text-indigo-400" />
        <h3 className="text-xs font-black text-white uppercase tracking-widest">Semantic Firewall Analysis</h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        
        {/* Agent Intent */}
        <div className="bg-black p-4 rounded-xl border border-white/10 relative">
          <div className="absolute -top-3 left-4 px-2 bg-black text-[10px] font-bold text-slate-500 uppercase tracking-wider">
            Stated Agent Intent
          </div>
          <p className="text-sm text-slate-300 font-mono leading-relaxed">
            "{analysis.agentIntent}"
          </p>
        </div>

        {/* Arrow / Score */}
        <div className="flex flex-col items-center justify-center text-center">
           <div className={`text-2xl font-black ${color} tracking-tighter`}>
             {analysis.divergenceScore}%
           </div>
           <span className="text-[10px] font-black uppercase text-slate-500 tracking-widest mb-2">Divergence Score</span>
           
           {isDivergent ? (
             <div className="flex items-center gap-1 text-rose-500 text-xs font-bold uppercase tracking-wider bg-rose-500/10 px-3 py-1 rounded-full border border-rose-500/20">
               <Split size={12} /> Semantic Drift
             </div>
           ) : (
             <div className="flex items-center gap-1 text-emerald-500 text-xs font-bold uppercase tracking-wider bg-emerald-500/10 px-3 py-1 rounded-full border border-emerald-500/20">
               <CheckCircle size={12} /> Alignment
             </div>
           )}
        </div>

        {/* Real Action */}
        <div className={`p-4 rounded-xl border relative ${isDivergent ? 'bg-rose-950/20 border-rose-500/30' : 'bg-emerald-950/20 border-emerald-500/30'}`}>
           <div className="absolute -top-3 left-4 px-2 bg-slate-900 text-[10px] font-bold text-slate-500 uppercase tracking-wider">
             Detected Reality
           </div>
           <p className={`text-sm font-mono leading-relaxed ${isDivergent ? 'text-rose-300' : 'text-emerald-300'}`}>
             "{analysis.executedAction}"
           </p>
        </div>
      </div>

      {/* Analysis Text */}
      <div className={`p-4 rounded-xl text-xs font-mono border-l-2 ${isDivergent ? 'border-rose-500 bg-rose-500/5 text-rose-200' : 'border-emerald-500 bg-emerald-500/5 text-emerald-200'}`}>
        <strong className="uppercase mr-2">Analyst Note:</strong>
        {analysis.analysis}
      </div>
    </div>
  );
};

export default SemanticFirewall;
