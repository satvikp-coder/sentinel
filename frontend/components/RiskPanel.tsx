
import React from 'react';
import { AgentAction, RiskLevel, ActionStatus } from '../types';
import { AlertTriangle, CheckCircle, ShieldAlert, Info, HelpCircle, Flag } from 'lucide-react';
import { playSound } from '../utils/sound';

interface RiskPanelProps {
  action?: AgentAction;
  onMediate?: (actionId: string, decision: ActionStatus) => void;
}

const RiskPanel: React.FC<RiskPanelProps> = ({ action, onMediate }) => {
  if (!action) {
    return (
      <div className="h-full rounded-3xl bg-slate-900 border border-white/5 flex flex-col items-center justify-center text-slate-500 p-8 text-center">
        <HelpCircle size={48} className="mb-6 opacity-20" />
        <p className="font-bold uppercase tracking-widest text-xs">Select Node to Inspect</p>
      </div>
    );
  }

  const isHighRisk = action.riskScore >= 70;
  const isMediumRisk = action.riskScore >= 30 && action.riskScore < 70;

  let headerColor = 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400';
  let glow = 'shadow-[0_0_20px_rgba(16,185,129,0.1)]';

  if (isHighRisk) {
    headerColor = 'bg-rose-500/10 border-rose-500/20 text-rose-500';
    glow = 'shadow-[0_0_20px_rgba(244,63,94,0.1)]';
  } else if (isMediumRisk) {
    headerColor = 'bg-amber-500/10 border-amber-500/20 text-amber-500';
    glow = 'shadow-[0_0_20px_rgba(245,158,11,0.1)]';
  }

  const handleMediate = (decision: ActionStatus) => {
    if (onMediate) {
      playSound(decision === ActionStatus.ALLOWED ? 'CLICK' : 'BLOCK');
      onMediate(action.id, decision);
    }
  };

  return (
    <div className="h-full flex flex-col bg-slate-900 border border-white/5 rounded-3xl overflow-hidden shadow-2xl">
      {/* Score Header */}
      <div className={`p-8 border-b ${headerColor.split(' ')[1]} ${glow} relative overflow-hidden`}>
        <div className={`absolute inset-0 opacity-20 ${headerColor.split(' ')[0]}`}></div>

        <div className="relative z-10">
          <div className="flex items-center justify-between mb-4">
            <span className="text-[10px] font-black uppercase tracking-[0.2em] opacity-80 text-white">Risk Assessment</span>
            {isHighRisk ? <ShieldAlert size={24} className="text-rose-500 animate-pulse" /> : <CheckCircle size={24} className="text-emerald-500" />}
          </div>
          <div className="flex items-baseline space-x-2">
            <span className={`text-6xl font-black tracking-tighter ${isHighRisk ? 'text-rose-500' : 'text-emerald-500'}`}>{action.riskScore}</span>
            <span className="text-sm opacity-60 font-mono text-white">/100</span>
          </div>
          <p className={`text-xs mt-2 font-bold uppercase tracking-widest ${isHighRisk ? 'text-rose-400' : 'text-emerald-400'}`}>{action.riskLevel} SEVERITY</p>
        </div>
      </div>

      <div className="p-6 space-y-8 overflow-y-auto custom-scrollbar flex-1">
        {/* Threat Explanation */}
        <div>
          <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3 flex items-center gap-2">
            <Info size={14} className="text-indigo-500" />
            Detection Logic
          </h4>
          <p className="text-sm text-slate-300 leading-relaxed bg-slate-950 p-4 rounded-xl border border-white/5 font-mono">
            <span className="text-indigo-400 mr-2">&gt;</span>{action.explanation}
          </p>
        </div>

        {/* Detected Modules */}
        <div>
          <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3">Triggered Heuristics</h4>
          <div className="space-y-2">
            {action.detectedThreats.length > 0 ? action.detectedThreats.map(threat => (
              <div key={threat} className="flex items-center text-xs font-mono font-bold text-rose-400 bg-rose-500/5 px-4 py-3 rounded-xl border border-rose-500/20">
                <AlertTriangle size={14} className="mr-3 text-rose-500" />
                {threat}
              </div>
            )) : (
              <div className="text-xs font-mono font-bold text-emerald-400 bg-emerald-500/5 px-4 py-3 rounded-xl border border-emerald-500/20 flex items-center">
                <CheckCircle size={14} className="mr-3 text-emerald-500" />
                No Active Threats
              </div>
            )}
          </div>
        </div>

        {/* Mediation Controls (Only if blocked or pending) */}
        {(action.status === ActionStatus.BLOCKED || action.status === ActionStatus.PENDING) && onMediate && (
          <div className="pt-6 border-t border-white/5 space-y-4">
            <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Mediation Protocol</h4>
            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={() => handleMediate(ActionStatus.ALLOWED)}
                className="py-3 px-4 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold uppercase tracking-wider rounded-xl shadow-lg shadow-indigo-500/20 transition-all"
              >
                Force Allow
              </button>
              <button
                className="py-3 px-4 bg-slate-800 border border-white/5 text-slate-300 hover:bg-slate-700 text-xs font-bold uppercase tracking-wider rounded-xl transition-all"
              >
                Sandbox
              </button>
            </div>

            {/* False Positive Reporting Loop */}
            <button
              className="w-full flex items-center justify-center space-x-2 py-2 text-[10px] font-bold uppercase tracking-widest text-slate-500 hover:text-white transition-colors border border-dashed border-white/10 hover:border-white/30 rounded-lg"
              onClick={() => {
                alert('Incident flagged as False Positive. Model weights updated.');
                playSound('CLICK');
              }}
            >
              <Flag size={12} />
              <span>Report False Positive</span>
            </button>

            <p className="text-[10px] text-slate-600 mt-4 text-center font-mono">
              AUTH: SENIOR_ANALYST_KEY_229
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default RiskPanel;
