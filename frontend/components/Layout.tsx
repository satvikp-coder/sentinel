
import React, { useState, useEffect } from 'react';
import { Shield, Activity, Play, BarChart3, LayoutDashboard, User, Lock, Zap, AlertOctagon, Terminal, FileText, LogOut, Sliders, Siren, Volume2, VolumeX } from 'lucide-react';
import { DefconLevel } from '../types';
import LatencyTicker from './LatencyTicker';
import KeyboardHelp from './KeyboardHelp';
import { playSound, toggleMute } from '../utils/sound';

interface LayoutProps {
  children: React.ReactNode;
  activePage: string;
  onNavigate: (page: string) => void;
  onLogout: () => void;
  defconLevel?: DefconLevel; // Prop to control global threat state
}

const Layout: React.FC<LayoutProps> = ({ children, activePage, onNavigate, onLogout, defconLevel = DefconLevel.FIVE }) => {
  const [securityActive, setSecurityActive] = useState(true);
  const [isMuted, setIsMuted] = useState(false);
  const [hackerMode, setHackerMode] = useState(false);

  // Global Keyboard Listeners (Hacker Mode)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Toggle Hacker Mode Help on '?' or 'H'
      if (e.key === '?' || (e.key === 'h' && e.ctrlKey)) {
        setHackerMode(prev => !prev);
        playSound('CLICK');
      }

      // Operational Shortcuts
      if (e.key.toLowerCase() === 'k' && e.shiftKey) {
        // Kill Switch Simulation
        playSound('ALARM');
        alert('KILL SWITCH ACTIVATED: ALL AGENTS TERMINATED');
      }
      if (e.key.toLowerCase() === 'd' && e.shiftKey) {
        onNavigate('demo');
        playSound('CLICK');
      }
      if (e.key.toLowerCase() === 'x' && e.shiftKey) {
         // Broadcast X-Ray Toggle (Mocked via console for now, components listen to props)
         console.log('Global X-Ray Toggle Signal');
         playSound('PING');
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onNavigate]);

  const handleMuteToggle = () => {
    const muted = toggleMute();
    setIsMuted(muted);
    if (!muted) playSound('CLICK');
  };

  // Dynamic Theme based on DEFCON
  const getThemeColors = () => {
    switch(defconLevel) {
      case DefconLevel.ONE: // CRITICAL
        return {
          bg: 'bg-red-950/20',
          border: 'border-red-500/30',
          text: 'text-red-500',
          glow: 'shadow-[0_0_30px_rgba(239,68,68,0.2)]',
          pulse: 'animate-[pulse_1s_ease-in-out_infinite]'
        };
      case DefconLevel.THREE: // ELEVATED
        return {
          bg: 'bg-amber-950/20',
          border: 'border-amber-500/30',
          text: 'text-amber-500',
          glow: 'shadow-[0_0_20px_rgba(245,158,11,0.2)]',
          pulse: 'animate-pulse'
        };
      default: // NORMAL
        return {
          bg: 'bg-slate-950/80',
          border: 'border-white/5',
          text: 'text-indigo-400',
          glow: 'shadow-[0_0_15px_rgba(99,102,241,0.2)]',
          pulse: ''
        };
    }
  };

  const theme = getThemeColors();

  return (
    <div className={`min-h-screen bg-slate-950 text-slate-200 flex flex-col font-sans selection:bg-indigo-500/30 transition-colors duration-700 ${!securityActive ? 'selection:bg-rose-500/30' : ''}`}>
      
      {/* CRT Scanline Overlay */}
      <div className="fixed inset-0 pointer-events-none z-50 crt-overlay opacity-50"></div>

      {/* Keyboard Helper */}
      <KeyboardHelp visible={hackerMode} />

      {/* Global DEFCON Overlay Effect */}
      {defconLevel === DefconLevel.ONE && (
        <div className="fixed inset-0 pointer-events-none z-50 border-[6px] border-red-600/20 animate-pulse"></div>
      )}

      {/* Top Navigation */}
      <header className={`h-20 flex items-center justify-between px-8 sticky top-0 z-30 backdrop-blur-md border-b transition-all duration-500 ${theme.bg} ${theme.border}`}>
        <div className="flex items-center space-x-4">
          <div className={`w-10 h-10 rounded-2xl flex items-center justify-center border transition-all duration-500 ${theme.bg} ${theme.text} ${theme.border} ${theme.glow}`}>
            {securityActive ? <Shield size={20} strokeWidth={3} className={theme.pulse} /> : <AlertOctagon size={20} strokeWidth={3} />}
          </div>
          <div className="flex flex-col">
            <span className="font-black text-xl tracking-tighter text-white uppercase">Sentinel</span>
            <div className="flex items-center gap-2">
               <span className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-500">Research Prototype</span>
               {defconLevel !== DefconLevel.FIVE && (
                 <span className={`text-[8px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded ${theme.bg} ${theme.text} border ${theme.border}`}>
                   DEFCON {defconLevel === DefconLevel.ONE ? '1' : '3'}
                 </span>
               )}
            </div>
          </div>
        </div>
        
        <div className="flex items-center space-x-6">
          <LatencyTicker />

          {/* Sound Toggle */}
          <button 
            onClick={handleMuteToggle}
            className="p-2 rounded-lg bg-slate-900 border border-white/5 text-slate-500 hover:text-white transition-colors"
            title="Toggle Audio Cues"
          >
            {isMuted ? <VolumeX size={16} /> : <Volume2 size={16} />}
          </button>

          {/* Failure Mode Simulator */}
          <button 
            onClick={() => { setSecurityActive(!securityActive); playSound('CLICK'); }}
            className={`flex items-center space-x-2 px-4 py-2 rounded-full border transition-all duration-300 ${
              securityActive 
                ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.1)]' 
                : 'bg-rose-500/10 border-rose-500/20 text-rose-500 shadow-[0_0_15px_rgba(244,63,94,0.2)] animate-pulse'
            }`}
          >
            {securityActive ? <Lock size={12} strokeWidth={3} /> : <AlertOctagon size={12} strokeWidth={3} />}
            <span className="text-[10px] font-black uppercase tracking-widest">{securityActive ? 'Security Layer Active' : 'SECURITY DISABLED'}</span>
          </button>

          {/* Cognitive Load Indicator */}
          <div className="hidden md:flex items-center space-x-2 px-3 py-1.5 bg-slate-900 rounded-lg border border-white/5" title="Analyst Cognitive Load Monitor">
            <Activity size={12} className={defconLevel === DefconLevel.ONE ? 'text-red-500 animate-bounce' : 'text-sky-400'} />
            <div className="flex flex-col">
              <span className="text-[8px] uppercase font-black text-slate-500 tracking-wider">Analyst Load</span>
              <span className={`text-[10px] font-bold ${defconLevel === DefconLevel.ONE ? 'text-red-500' : 'text-sky-400'}`}>
                {defconLevel === DefconLevel.ONE ? 'CRITICAL' : 'OPTIMAL'}
              </span>
            </div>
          </div>

          <div className="w-10 h-10 rounded-2xl bg-slate-900 flex items-center justify-center text-slate-400 border border-white/5 hover:border-white/10 hover:text-white transition-colors cursor-pointer">
            <User size={18} />
          </div>
        </div>
      </header>

      {!securityActive && (
        <div className="bg-rose-600/20 border-b border-rose-500/30 py-1 text-center relative z-40">
           <p className="text-[10px] font-black text-rose-200 uppercase tracking-[0.2em] animate-pulse">
             ⚠ WARNING: FAILURE MODE SIMULATION ACTIVE - AGENTS EXPOSED TO RAW WEB ⚠
           </p>
        </div>
      )}

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside className="w-72 bg-slate-950 flex flex-col pt-8 pb-8 px-6 border-r border-white/5">
          <div className="mb-8 px-2 text-[10px] font-black text-slate-600 uppercase tracking-[0.2em]">
            System Modules
          </div>
          <nav className="flex-1 space-y-2">
            <NavItem 
              icon={<LayoutDashboard size={18} />} 
              label="Session Monitor" 
              active={activePage === 'dashboard'} 
              onClick={() => onNavigate('dashboard')} 
            />
            <NavItem 
              icon={<Play size={18} />} 
              label="Attack Demo Mode" 
              active={activePage === 'demo'} 
              onClick={() => onNavigate('demo')} 
            />
            <NavItem 
              icon={<Sliders size={18} />} 
              label="Policy Sandbox" 
              active={activePage === 'policy'} 
              onClick={() => onNavigate('policy')} 
            />
            <NavItem 
              icon={<BarChart3 size={18} />} 
              label="Evaluation Metrics" 
              active={activePage === 'evaluation'} 
              onClick={() => onNavigate('evaluation')} 
            />
            <NavItem 
              icon={<FileText size={18} />} 
              label="Audit Logs" 
              active={activePage === 'audit'} 
              onClick={() => onNavigate('audit')} 
            />
          </nav>
          
          <div className="mt-auto space-y-4">
            {/* Hacker Mode Tip */}
            <div onClick={() => setHackerMode(true)} className="px-4 py-2 bg-slate-900/50 rounded-xl border border-dashed border-white/5 text-[9px] text-slate-500 text-center cursor-pointer hover:text-indigo-400 transition-colors">
              Press <span className="font-bold text-white">?</span> for shortcuts
            </div>

            <div className={`rounded-3xl p-5 border backdrop-blur-sm transition-colors duration-500 ${defconLevel === DefconLevel.ONE ? 'bg-red-950/20 border-red-500/30' : 'bg-slate-900/50 border-white/5'}`}>
              <h4 className="text-white font-bold text-sm flex items-center gap-2 mb-3">
                {defconLevel === DefconLevel.ONE ? <Siren size={16} className="text-red-500 animate-pulse" /> : <Zap size={16} className="text-amber-500" />}
                <span className="tracking-tight uppercase">System Health</span>
              </h4>
              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-slate-500 font-mono">ENFORCEMENT</span>
                  <span className={`${defconLevel === DefconLevel.ONE ? 'text-red-500' : 'text-emerald-500'} font-mono`}>
                    {defconLevel === DefconLevel.ONE ? 'COMPROMISED' : '100%'}
                  </span>
                </div>
                <div className="flex justify-between items-center text-xs">
                  <span className="text-slate-500 font-mono">TRUST SCORE</span>
                  <span className={`${defconLevel === DefconLevel.ONE ? 'text-red-500' : 'text-indigo-400'} font-mono`}>
                     {defconLevel === DefconLevel.ONE ? 'CRITICAL' : '98/100'}
                  </span>
                </div>
              </div>
            </div>
            
            <button 
              onClick={onLogout}
              className="w-full flex items-center justify-center space-x-2 px-4 py-3 rounded-2xl bg-slate-900 border border-white/5 text-slate-400 hover:text-rose-400 hover:border-rose-500/30 transition-all text-xs font-bold uppercase tracking-wider"
            >
              <LogOut size={16} />
              <span>Terminate Session</span>
            </button>
          </div>
        </aside>

        {/* Main Content */}
        <main className={`flex-1 overflow-y-auto p-8 relative custom-scrollbar transition-colors duration-700 ${!securityActive ? 'bg-rose-950/10' : 'bg-black'}`}>
          {children}
        </main>
      </div>
    </div>
  );
};

const NavItem = ({ icon, label, active, onClick }: { icon: React.ReactNode, label: string, active: boolean, onClick: () => void }) => (
  <button
    onClick={() => { onClick(); playSound('HOVER'); }}
    onMouseEnter={() => playSound('HOVER')}
    className={`w-full flex items-center space-x-3 px-4 py-4 rounded-2xl transition-all duration-200 group ${
      active 
        ? 'bg-indigo-600/10 text-indigo-400 border border-indigo-500/20 shadow-[0_0_15px_rgba(99,102,241,0.1)]' 
        : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200 border border-transparent hover:border-white/5'
    }`}
  >
    <span className={`${active ? 'text-indigo-400' : 'text-slate-500 group-hover:text-slate-300'}`}>
      {icon}
    </span>
    <span className="text-xs font-bold uppercase tracking-wider">{label}</span>
    {active && <div className="ml-auto w-1.5 h-1.5 rounded-full bg-indigo-500 shadow-[0_0_8px_#6366f1]" />}
  </button>
);

export default Layout;
