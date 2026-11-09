
import React, { useState } from 'react';
import { ShieldAlert, Check } from 'lucide-react';

interface SafetyPledgeModalProps {
  onConfirm: () => void;
}

const SafetyPledgeModal: React.FC<SafetyPledgeModalProps> = ({ onConfirm }) => {
  const [accepted, setAccepted] = useState(false);

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/95 backdrop-blur-md animate-in fade-in duration-500">
      <div className="bg-slate-900 w-full max-w-lg rounded-3xl border border-white/10 shadow-2xl overflow-hidden relative">
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-indigo-500 to-transparent"></div>
        
        <div className="p-10 text-center">
          <div className="w-16 h-16 bg-slate-800 rounded-full flex items-center justify-center mx-auto mb-6 border border-white/5 shadow-[0_0_30px_rgba(99,102,241,0.15)]">
            <ShieldAlert size={32} className="text-indigo-400" />
          </div>
          
          <h2 className="text-2xl font-black text-white uppercase tracking-tighter mb-2">AI Safety Protocol</h2>
          <p className="text-slate-400 text-sm mb-8 font-mono">Operator Acknowledgment Required</p>

          <div className="bg-black/50 p-6 rounded-2xl border border-white/5 text-left mb-8">
            <p className="text-slate-300 text-sm leading-relaxed mb-4">
              You are accessing <strong className="text-white">SECUREAGENT</strong>, a control plane for autonomous browser agents.
            </p>
            <ul className="space-y-3 text-xs text-slate-400">
              <li className="flex gap-2">
                <span className="text-indigo-500">►</span> All agent actions are auditable and immutable.
              </li>
              <li className="flex gap-2">
                <span className="text-indigo-500">►</span> You are responsible for the tasks assigned to agents.
              </li>
              <li className="flex gap-2">
                <span className="text-indigo-500">►</span> Malicious use of this platform is strictly prohibited.
              </li>
            </ul>
          </div>

          <label className="flex items-center justify-center space-x-3 cursor-pointer mb-8 group">
            <div className={`w-5 h-5 rounded border flex items-center justify-center transition-all ${accepted ? 'bg-indigo-600 border-indigo-500' : 'border-slate-600 group-hover:border-slate-400'}`}>
              {accepted && <Check size={14} className="text-white" />}
            </div>
            <input 
              type="checkbox" 
              className="hidden" 
              checked={accepted} 
              onChange={(e) => setAccepted(e.target.checked)} 
            />
            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider select-none">I Pledge to uphold AI Safety Standards</span>
          </label>

          <button 
            disabled={!accepted}
            onClick={onConfirm}
            className={`w-full py-4 rounded-xl font-bold uppercase tracking-widest text-xs transition-all ${
              accepted 
                ? 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-[0_0_20px_rgba(99,102,241,0.3)]' 
                : 'bg-slate-800 text-slate-500 cursor-not-allowed'
            }`}
          >
            Access Control Plane
          </button>
        </div>
      </div>
    </div>
  );
};

export default SafetyPledgeModal;
