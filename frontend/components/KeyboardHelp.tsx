
import React from 'react';
import { Command } from 'lucide-react';

interface KeyboardHelpProps {
  visible: boolean;
}

const KeyboardHelp: React.FC<KeyboardHelpProps> = ({ visible }) => {
  if (!visible) return null;

  const shortcuts = [
    { key: 'K', desc: 'Kill Switch' },
    { key: 'X', desc: 'Toggle X-Ray' },
    { key: 'D', desc: 'Demo Mode' },
    { key: 'R', desc: 'Time Travel' },
    { key: 'SPACE', desc: 'Pause Agent' },
  ];

  return (
    <div className="fixed bottom-6 right-6 z-50 animate-in slide-in-from-right-4 duration-300">
      <div className="bg-slate-900/90 backdrop-blur-md border border-indigo-500/30 rounded-2xl p-4 shadow-2xl">
        <div className="flex items-center gap-2 mb-3 pb-2 border-b border-white/10">
          <Command size={14} className="text-indigo-500" />
          <span className="text-[10px] font-black uppercase tracking-widest text-indigo-400">Hacker Mode Active</span>
        </div>
        <div className="space-y-2">
          {shortcuts.map(s => (
            <div key={s.key} className="flex justify-between items-center gap-8">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">{s.desc}</span>
              <kbd className="bg-slate-800 border border-white/10 px-2 py-0.5 rounded text-[10px] font-mono text-white min-w-[24px] text-center">
                {s.key}
              </kbd>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default KeyboardHelp;
