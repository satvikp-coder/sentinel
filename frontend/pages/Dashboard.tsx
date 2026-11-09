
import React, { useState } from 'react';
import { MOCK_SESSIONS } from '../services/mockData';
import SessionCard from '../components/SessionCard';
import SystemFlowVisual from '../components/SystemFlowVisual';
import NewAgentModal from '../components/NewAgentModal';
import MetaphorView from '../components/MetaphorView';
import { Plus, Filter, LayoutGrid, Box } from 'lucide-react';

interface DashboardProps {
  onSessionSelect: (id: string) => void;
}

const Dashboard: React.FC<DashboardProps> = ({ onSessionSelect }) => {
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [modeFilter, setModeFilter] = useState<string>('ALL');
  const [showNewAgentModal, setShowNewAgentModal] = useState(false);
  const [viewMode, setViewMode] = useState<'STANDARD' | 'METAPHOR'>('STANDARD');

  const filteredSessions = MOCK_SESSIONS.filter(session => {
    if (statusFilter !== 'ALL' && session.status !== statusFilter) return false;
    if (modeFilter !== 'ALL' && session.mode !== modeFilter) return false;
    return true;
  });

  const handleLaunchAgent = (config: any) => {
    console.log('Launching agent:', config);
    setShowNewAgentModal(false);
  };

  return (
    <div className="max-w-7xl mx-auto pt-6 pb-12">
      {/* Header */}
      <div className="flex items-end justify-between mb-8">
        <div>
          <h1 className="text-5xl font-black text-white uppercase tracking-tighter mb-2">Agent Sessions</h1>
          <p className="text-sm text-slate-400 font-mono">Monitor active browser agents and security incidents.</p>
        </div>
        <div className="flex gap-4">
           {/* View Toggle */}
           <div className="bg-slate-900 p-1 rounded-xl border border-white/5 flex">
             <button 
               onClick={() => setViewMode('STANDARD')}
               className={`p-3 rounded-lg transition-all ${viewMode === 'STANDARD' ? 'bg-indigo-600 text-white shadow-lg' : 'text-slate-500 hover:text-white'}`}
             >
               <LayoutGrid size={16} />
             </button>
             <button 
               onClick={() => setViewMode('METAPHOR')}
               className={`p-3 rounded-lg transition-all ${viewMode === 'METAPHOR' ? 'bg-indigo-600 text-white shadow-lg' : 'text-slate-500 hover:text-white'}`}
             >
               <Box size={16} />
             </button>
           </div>
           
           <button 
            onClick={() => setShowNewAgentModal(true)}
            className="flex items-center space-x-3 bg-indigo-600 hover:bg-indigo-500 text-white px-6 py-4 rounded-2xl font-bold uppercase tracking-wider text-xs shadow-[0_0_20px_rgba(79,70,229,0.3)] transition-all hover:shadow-[0_0_30px_rgba(79,70,229,0.5)] border border-indigo-400/20"
          >
            <Plus size={16} strokeWidth={3} />
            <span>New Agent Task</span>
          </button>
        </div>
      </div>

      {/* Scoreboard Widget */}
      <div className="grid grid-cols-4 gap-4 mb-8">
        <ScoreCard label="Active Agents" value="3" color="text-white" />
        <ScoreCard label="Attacks Blocked" value="142" color="text-indigo-400" />
        <ScoreCard label="Trust Score Avg" value="88" color="text-emerald-400" />
        <ScoreCard label="Overrides" value="2" color="text-rose-400" />
      </div>

      {viewMode === 'STANDARD' ? (
        <>
          <SystemFlowVisual />

          {/* Filters Bar */}
          <div className="flex flex-wrap items-center gap-4 mb-10 animate-in fade-in slide-in-from-bottom-2 duration-500">
            <div className="flex items-center gap-2 px-4 py-3 bg-slate-900 border border-white/5 rounded-2xl">
              <Filter size={14} className="text-indigo-400" />
              <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Filters</span>
            </div>

            <div className="flex p-1 bg-slate-900 border border-white/5 rounded-2xl">
              {['ALL', 'RUNNING', 'BLOCKED', 'COMPLETED'].map((status) => (
                <button
                  key={status}
                  onClick={() => setStatusFilter(status)}
                  className={`px-5 py-2.5 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${
                    statusFilter === status 
                      ? 'bg-slate-800 text-white shadow-lg shadow-black/20 ring-1 ring-white/5' 
                      : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'
                  }`}
                >
                  {status}
                </button>
              ))}
            </div>

            <div className="w-px h-8 bg-white/5 hidden md:block"></div>

            <div className="flex p-1 bg-slate-900 border border-white/5 rounded-2xl">
              {['ALL', 'HEADLESS', 'VISIBLE'].map((mode) => (
                <button
                  key={mode}
                  onClick={() => setModeFilter(mode)}
                  className={`px-5 py-2.5 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${
                    modeFilter === mode 
                      ? 'bg-slate-800 text-white shadow-lg shadow-black/20 ring-1 ring-white/5' 
                      : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'
                  }`}
                >
                  {mode}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {filteredSessions.map(session => (
              <SessionCard 
                key={session.id} 
                session={session} 
                onClick={onSessionSelect} 
              />
            ))}
          </div>
        </>
      ) : (
        <div className="animate-in zoom-in duration-500">
           <MetaphorView />
           <p className="text-center text-slate-500 font-mono text-xs mt-4 uppercase tracking-widest">Visualizing Abstract Security Plane</p>
        </div>
      )}

      {showNewAgentModal && (
        <NewAgentModal onClose={() => setShowNewAgentModal(false)} onLaunch={handleLaunchAgent} />
      )}
    </div>
  );
};

const ScoreCard = ({ label, value, color }: { label: string, value: string, color: string }) => (
  <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 text-center shadow-lg group hover:border-indigo-500/20 transition-all">
    <div className={`text-3xl font-black tracking-tighter ${color} mb-1 group-hover:scale-110 transition-transform duration-300`}>{value}</div>
    <div className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-500">{label}</div>
  </div>
);

export default Dashboard;
