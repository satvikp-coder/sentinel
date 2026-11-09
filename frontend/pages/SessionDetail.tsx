
import React, { useState, useEffect } from 'react';
import { MOCK_SESSIONS, MOCK_DOM_TREE } from '../services/mockData';
import { Session, AgentAction, DomNode } from '../types';
import DomVisualizer from '../components/DomVisualizer';
import RiskPanel from '../components/RiskPanel';
import SemanticFirewall from '../components/SemanticFirewall';
import EnvironmentAlert from '../components/EnvironmentAlert';
import { useToast } from '../components/Toast';
import { ArrowLeft, Play, Pause, Shield, Activity, ShieldCheck, Download, Rewind, Image as ImageIcon, Code } from 'lucide-react';

interface SessionDetailProps {
  sessionId: string;
  onBack: () => void;
}

const SessionDetail: React.FC<SessionDetailProps> = ({ sessionId, onBack }) => {
  const { showToast } = useToast();
  const [session, setSession] = useState<Session | undefined>();
  const [selectedAction, setSelectedAction] = useState<AgentAction | undefined>();
  const [highlightedDomId, setHighlightedDomId] = useState<string | undefined>();
  const [showScreenshot, setShowScreenshot] = useState(false);
  
  // Replay State
  const [timelineIndex, setTimelineIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);

  useEffect(() => {
    const found = MOCK_SESSIONS.find(s => s.id === sessionId);
    setSession(found);
    if (found && found.actions.length > 0) {
      setTimelineIndex(found.actions.length - 1);
      const latest = found.actions[found.actions.length - 1];
      handleActionSelect(latest);
    }
  }, [sessionId]);

  // Replay Logic
  useEffect(() => {
    let interval: any;
    if (isPlaying && session) {
      interval = setInterval(() => {
        setTimelineIndex(prev => {
          if (prev >= session.actions.length - 1) {
            setIsPlaying(false);
            return prev;
          }
          const next = prev + 1;
          handleActionSelect(session.actions[next]);
          return next;
        });
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [isPlaying, session]);

  const handleActionSelect = (action: AgentAction) => {
    setSelectedAction(action);
    setHighlightedDomId(action.relatedDomNodeId);
  };

  const handleTimelineScrub = (idx: number) => {
    setTimelineIndex(idx);
    if (session) handleActionSelect(session.actions[idx]);
  };

  const handleDomClick = (node: DomNode) => {
    setHighlightedDomId(node.id);
    const relatedAction = session?.actions.find(a => a.relatedDomNodeId === node.id);
    if (relatedAction) setSelectedAction(relatedAction);
    else setSelectedAction(undefined);
  };

  const handleExport = () => {
    showToast("Generating Forensic Report...", "INFO");
    setTimeout(() => {
      showToast("Report Exported: report_sess_001.pdf", "SUCCESS");
    }, 1500);
  };

  const visibleActions = session ? session.actions.slice(0, timelineIndex + 1) : [];

  if (!session) return <div className="text-white font-mono">Initializing Stream...</div>;

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)]"> 
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center space-x-6">
          <button onClick={onBack} className="w-12 h-12 rounded-2xl bg-slate-900 border border-white/5 flex items-center justify-center text-slate-400 hover:text-white hover:border-white/20 transition-all">
            <ArrowLeft size={20} />
          </button>
          <div>
            <div className="flex items-center gap-3 mb-1">
              <h2 className="text-2xl font-black text-white uppercase tracking-tighter">
                Session {session.id.split('-')[1]}
              </h2>
              {/* Trust Score Badge */}
              <div className="flex items-center space-x-1.5 bg-slate-800 px-3 py-1 rounded-full border border-white/5">
                <ShieldCheck size={14} className={session.trustScore > 70 ? 'text-emerald-400' : 'text-amber-400'} />
                <span className={`text-xs font-bold font-mono ${session.trustScore > 70 ? 'text-emerald-400' : 'text-amber-400'}`}>
                  Trust: {session.trustScore}
                </span>
              </div>
            </div>
            <p className="text-xs text-slate-500 font-mono">{session.targetUrl}</p>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
           {/* Export Report */}
           <button 
             onClick={handleExport}
             className="flex items-center space-x-2 px-4 py-3 bg-slate-900 border border-white/5 rounded-xl hover:bg-slate-800 transition-colors text-xs font-bold text-slate-300 uppercase tracking-wide"
           >
             <Download size={14} />
             <span>Export Report</span>
           </button>

           <div className="bg-slate-900 rounded-2xl px-6 py-3 border border-white/5 flex items-center gap-4">
             <div className="text-right">
               <div className="text-[10px] text-slate-500 uppercase font-black tracking-widest">Risk Level</div>
               <div className={`font-mono font-bold text-xl ${session.riskScoreAvg > 50 ? 'text-rose-500 drop-shadow-[0_0_8px_rgba(244,63,94,0.5)]' : 'text-emerald-500 drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]'}`}>
                 {session.riskScoreAvg}/100
               </div>
             </div>
             <Activity className={session.riskScoreAvg > 50 ? 'text-rose-500' : 'text-emerald-500'} size={24} />
          </div>
        </div>
      </div>

      {/* 3-Pane Layout with gaps */}
      <div className="flex flex-1 gap-6 overflow-hidden">
        
        {/* Left: Timeline & Replay */}
        <div className="w-80 bg-slate-900 border border-white/5 rounded-3xl overflow-hidden flex flex-col">
          <div className="p-5 border-b border-white/5 bg-slate-900/50 backdrop-blur sticky top-0 z-10">
            <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-2 mb-4">
              <Rewind size={12} className="text-indigo-500" /> Threat Replay
            </h3>
            
            {/* Replay Controls */}
            <div className="flex items-center gap-3 mb-2">
               <button 
                 onClick={() => setIsPlaying(!isPlaying)}
                 className="w-8 h-8 rounded-full bg-indigo-600 flex items-center justify-center text-white hover:bg-indigo-500 transition-colors"
               >
                 {isPlaying ? <Pause size={14} fill="currentColor" /> : <Play size={14} fill="currentColor" className="ml-0.5" />}
               </button>
               <input 
                 type="range" 
                 min="0" 
                 max={session.actions.length - 1} 
                 value={timelineIndex}
                 onChange={(e) => handleTimelineScrub(parseInt(e.target.value))}
                 className="flex-1 h-1.5 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-indigo-500"
               />
            </div>
            <div className="flex justify-between text-[8px] font-mono text-slate-500">
               <span>START</span>
               <span>LIVE</span>
            </div>
          </div>

          <div className="p-4 space-y-3 overflow-y-auto custom-scrollbar flex-1">
            {visibleActions.map((action) => (
              <div 
                key={action.id}
                onClick={() => handleActionSelect(action)}
                className={`relative p-4 rounded-xl cursor-pointer transition-all border animate-in slide-in-from-left-2 duration-300 ${
                  selectedAction?.id === action.id 
                    ? 'bg-indigo-600/10 border-indigo-500/30 shadow-[0_0_15px_rgba(99,102,241,0.1)]' 
                    : 'bg-slate-950/50 border-white/5 hover:border-white/10'
                }`}
              >
                <div className="flex justify-between items-start mb-2">
                  <div className="font-bold text-sm text-slate-200">{action.type}</div>
                  <div className="text-[10px] font-mono text-slate-500">{action.timestamp}</div>
                </div>
                <div className="text-[10px] text-slate-500 font-mono truncate mb-3 opacity-70">
                  {action.targetElement}
                </div>
                
                <div className="flex items-center justify-between">
                  <span className={`text-[10px] font-black uppercase tracking-widest px-2 py-1 rounded-md ${
                    action.riskScore > 70 ? 'bg-rose-500/10 text-rose-500 border border-rose-500/20' : 
                    action.riskScore > 30 ? 'bg-amber-500/10 text-amber-500 border border-amber-500/20' : 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20'
                  }`}>
                    Risk: {action.riskScore}
                  </span>
                  {action.status === 'BLOCKED' && <Shield size={12} className="text-rose-500" />}
                </div>
              </div>
            ))}
            {visibleActions.length === 0 && (
              <div className="text-center text-slate-600 text-xs py-12 font-mono">WAITING FOR AGENT...</div>
            )}
          </div>
        </div>

        {/* Center: DOM / Threat Viz / Semantic Analysis */}
        <div className="flex-1 bg-black border border-white/5 rounded-3xl overflow-hidden relative flex flex-col">
          {/* Toolbar */}
          <div className="absolute top-5 left-5 right-5 flex justify-between items-center z-20 pointer-events-none">
             <span className="bg-slate-900/90 text-slate-400 text-[10px] font-black uppercase tracking-widest px-3 py-1.5 rounded-lg border border-white/10 backdrop-blur shadow-lg">
               Forensic Inspector
             </span>
             
             <div className="flex gap-2 pointer-events-auto">
               <button 
                onClick={() => setShowScreenshot(false)}
                className={`p-2 rounded-lg border backdrop-blur transition-colors ${!showScreenshot ? 'bg-indigo-600 border-indigo-500 text-white' : 'bg-slate-900/80 border-white/10 text-slate-500'}`}
               >
                 <Code size={14} />
               </button>
               <button 
                onClick={() => setShowScreenshot(true)}
                className={`p-2 rounded-lg border backdrop-blur transition-colors ${showScreenshot ? 'bg-indigo-600 border-indigo-500 text-white' : 'bg-slate-900/80 border-white/10 text-slate-500'}`}
               >
                 <ImageIcon size={14} />
               </button>
             </div>
          </div>
          
          <div className="flex-1 overflow-y-auto p-8 pt-20 custom-scrollbar">
             {/* Blind Spot Warnings */}
             {session.riskScoreAvg > 80 && (
                <div className="mb-6">
                  <EnvironmentAlert type="IFRAME" />
                </div>
             )}

             {/* Semantic Firewall (If active for this action) */}
             {selectedAction?.semanticAnalysis && (
                <div className="mb-6 animate-in slide-in-from-top-4 duration-500">
                   <SemanticFirewall analysis={selectedAction.semanticAnalysis} />
                </div>
             )}

             {/* DOM Tree vs Screenshot */}
             {showScreenshot ? (
               <div className="w-full h-full flex items-center justify-center bg-slate-900/50 rounded-xl border border-white/5 border-dashed">
                 <div className="text-center">
                   <ImageIcon size={48} className="mx-auto text-slate-600 mb-4" />
                   <p className="text-slate-500 text-xs font-mono">Snapshot unavailable in prototype mode.</p>
                 </div>
               </div>
             ) : (
                <DomVisualizer 
                    node={MOCK_DOM_TREE} 
                    highlightedNodeId={highlightedDomId}
                    onNodeClick={handleDomClick}
                />
             )}
          </div>
        </div>

        {/* Right: Risk Panel */}
        <div className="w-96">
          <RiskPanel 
            action={selectedAction} 
            onMediate={(id, decision) => showToast(`Action ${decision}: Policy Updated`, "SUCCESS")}
          />
        </div>

      </div>
    </div>
  );
};

export default SessionDetail;
