
import React from 'react';
import { Session } from '../types';
import { Globe, Clock, Eye, EyeOff, AlertTriangle, ArrowRight, ShieldCheck } from 'lucide-react';

interface SessionCardProps {
  session: Session;
  onClick: (id: string) => void;
}

const SessionCard: React.FC<SessionCardProps> = ({ session, onClick }) => {
  const statusConfig = {
    RUNNING: {
      colors: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20',
      glow: 'shadow-[0_0_10px_rgba(99,102,241,0.1)]'
    },
    COMPLETED: {
      colors: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      glow: 'shadow-[0_0_10px_rgba(16,185,129,0.1)]'
    },
    BLOCKED: {
      colors: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
      glow: 'shadow-[0_0_10px_rgba(244,63,94,0.1)]'
    },
  };

  const config = statusConfig[session.status];
  
  // Trust Score Color Logic
  let trustColor = 'text-emerald-400';
  if (session.trustScore < 50) trustColor = 'text-rose-400';
  else if (session.trustScore < 80) trustColor = 'text-amber-400';

  return (
    <div 
      onClick={() => onClick(session.id)}
      className="bg-slate-900 border border-white/5 rounded-3xl p-6 flex flex-col h-full group hover:border-indigo-500/30 hover:shadow-[0_0_30px_rgba(99,102,241,0.05)] transition-all duration-300 cursor-pointer relative overflow-hidden"
    >
      <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/5 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2 group-hover:bg-indigo-500/10 transition-all duration-500"></div>

      <div className="flex justify-between items-start mb-6 relative z-10">
        <span className={`px-3 py-1.5 rounded-full text-[10px] font-black uppercase tracking-widest border ${config.colors} ${config.glow}`}>
          {session.status}
        </span>
        
        {/* Trust Badge */}
        <div className="flex items-center space-x-1.5 bg-black/40 px-2 py-1 rounded-lg border border-white/5 backdrop-blur-sm" title="Agent Trust Score">
           <ShieldCheck size={12} className={trustColor} />
           <span className={`text-[10px] font-bold font-mono ${trustColor}`}>{session.trustScore}</span>
        </div>
      </div>

      <h3 className="font-bold text-lg text-white mb-2 line-clamp-2 leading-tight group-hover:text-indigo-300 transition-colors relative z-10">
        {session.taskDescription}
      </h3>
      
      <div className="flex items-center text-xs text-slate-500 mb-6 space-x-2 font-mono relative z-10">
        <Globe size={12} />
        <span className="truncate max-w-[200px]">{session.targetUrl}</span>
      </div>

      <div className="mt-auto pt-5 border-t border-white/5 flex items-center justify-between relative z-10">
        <div className="flex items-center space-x-2 text-slate-500 text-[10px] font-bold uppercase tracking-wider">
          <Clock size={12} />
          <span>{new Date(session.startTime).toLocaleTimeString()}</span>
        </div>
        
        <div className="flex items-center gap-3">
          <div className="text-slate-600 group-hover:text-indigo-400 transition-colors">
            {session.mode === 'VISIBLE' ? <Eye size={16} /> : <EyeOff size={16} />}
          </div>
          {session.riskScoreAvg > 50 ? (
             <div className="flex items-center space-x-2 text-rose-400 text-[10px] font-black uppercase tracking-widest">
               <AlertTriangle size={12} />
               <span>Risk: {session.riskScoreAvg}%</span>
             </div>
          ) : (
            <div className="text-slate-600 group-hover:translate-x-1 transition-transform duration-300">
              <ArrowRight size={16} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SessionCard;
