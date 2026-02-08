
import React, { useState } from 'react';
import { X, Play, Globe, List, Shield, Eye, EyeOff } from 'lucide-react';

interface NewAgentModalProps {
  onClose: () => void;
  onLaunch: (config: any) => void;
}

const NewAgentModal: React.FC<NewAgentModalProps> = ({ onClose, onLaunch }) => {
  const [mode, setMode] = useState<'HEADLESS' | 'VISIBLE'>('HEADLESS');
  const [url, setUrl] = useState('');
  const [task, setTask] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onLaunch({ url, task, mode });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 w-full max-w-xl rounded-3xl border border-white/10 shadow-2xl overflow-hidden">
        <div className="p-6 border-b border-white/5 flex justify-between items-center bg-slate-950/50">
          <h3 className="text-xl font-black text-white uppercase tracking-tight flex items-center gap-2">
            <Play size={20} className="text-indigo-500" /> Launch New Agent
          </h3>
          <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors">
            <X size={24} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-8 space-y-6">
          <div className="space-y-2">
            <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-2">
              <Globe size={12} /> Target URL
            </label>
            <input 
              type="url" 
              required
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full bg-black border border-white/10 rounded-xl px-4 py-3 text-sm font-mono text-white focus:outline-none focus:border-indigo-500 transition-colors"
            />
          </div>

          <div className="space-y-2">
            <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-2">
              <List size={12} /> Task Description
            </label>
            <textarea 
              required
              placeholder="e.g. Login to the portal and extract the latest invoice..."
              value={task}
              onChange={(e) => setTask(e.target.value)}
              className="w-full bg-black border border-white/10 rounded-xl px-4 py-3 text-sm font-sans text-white focus:outline-none focus:border-indigo-500 transition-colors h-24 resize-none"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
             <div 
               onClick={() => setMode('HEADLESS')}
               className={`cursor-pointer p-4 rounded-xl border flex flex-col items-center justify-center space-y-2 transition-all ${mode === 'HEADLESS' ? 'bg-indigo-600/10 border-indigo-500/50 text-indigo-400' : 'bg-slate-950 border-white/5 text-slate-500 hover:border-white/10'}`}
             >
               <EyeOff size={24} />
               <span className="text-xs font-bold uppercase tracking-wider">Headless Mode</span>
             </div>
             <div 
               onClick={() => setMode('VISIBLE')}
               className={`cursor-pointer p-4 rounded-xl border flex flex-col items-center justify-center space-y-2 transition-all ${mode === 'VISIBLE' ? 'bg-indigo-600/10 border-indigo-500/50 text-indigo-400' : 'bg-slate-950 border-white/5 text-slate-500 hover:border-white/10'}`}
             >
               <Eye size={24} />
               <span className="text-xs font-bold uppercase tracking-wider">Visible Demo</span>
             </div>
          </div>

          <div className="pt-4 flex items-center justify-end">
            <button 
              type="submit"
              className="bg-indigo-600 hover:bg-indigo-500 text-white px-8 py-3 rounded-xl font-bold uppercase tracking-wider text-xs shadow-lg shadow-indigo-500/20 transition-all flex items-center gap-2"
            >
              <Shield size={16} /> Initialize Session
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default NewAgentModal;
