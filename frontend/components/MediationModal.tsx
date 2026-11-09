import React from 'react';
import { AgentAction } from '../types';
import { ShieldAlert, X } from 'lucide-react';

interface MediationModalProps {
  action: AgentAction | null;
  onResolve: (allowed: boolean) => void;
  onClose: () => void;
}

const MediationModal: React.FC<MediationModalProps> = ({ action, onResolve, onClose }) => {
  if (!action) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md">
      <div className="bg-slate-900 w-full max-w-lg rounded-3xl shadow-[0_0_50px_rgba(244,63,94,0.15)] border border-rose-500/30 overflow-hidden animate-in fade-in zoom-in duration-300">
        <div className="bg-rose-950/30 px-8 py-6 border-b border-rose-500/20 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="p-3 bg-rose-500/20 rounded-2xl text-rose-500 border border-rose-500/30">
              <ShieldAlert size={28} />
            </div>
            <div>
              <h3 className="text-xl font-black text-white uppercase tracking-tight">Security Interception</h3>
              <p className="text-xs text-rose-400 font-bold uppercase tracking-widest">High-risk action detected</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors">
            <X size={24} />
          </button>
        </div>

        <div className="p-8">
          <div className="mb-8">
            <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3">Action Details</h4>
            <div className="bg-black p-4 rounded-xl border border-white/10 font-mono text-sm text-slate-300">
              <p><span className="text-slate-600 select-none">TYPE  :: </span> {action.type}</p>
              <p><span className="text-slate-600 select-none">TGT   :: </span> {action.targetElement}</p>
              <p className="mt-3 text-rose-400 font-bold border-t border-white/10 pt-3">
                > {action.explanation}
              </p>
            </div>
          </div>

          <div className="bg-amber-500/5 p-4 rounded-xl border border-amber-500/20 mb-8">
             <h4 className="text-xs font-bold text-amber-500 uppercase tracking-wider mb-1">Safety Policy Triggered</h4>
             <p className="text-xs text-amber-200/70 font-mono">
               "Block interactions with hidden DOM elements containing imperative commands."
             </p>
          </div>

          <div className="flex space-x-4">
            <button 
              onClick={() => onResolve(false)}
              className="flex-1 bg-rose-600 hover:bg-rose-500 text-white text-sm font-bold uppercase tracking-wider py-4 rounded-xl transition-all shadow-[0_0_20px_rgba(244,63,94,0.3)]"
            >
              Block Action
            </button>
            <button 
              onClick={() => onResolve(true)}
              className="flex-1 bg-transparent border border-white/10 hover:bg-white/5 text-slate-300 text-sm font-bold uppercase tracking-wider py-4 rounded-xl transition-all"
            >
              Allow Override
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MediationModal;