
import React, { useEffect, useRef, useState } from 'react';
import { Terminal, Copy, Check } from 'lucide-react';

interface LiveCodeTerminalProps {
  codeSnippet: string;
  isScanning: boolean;
}

const LiveCodeTerminal: React.FC<LiveCodeTerminalProps> = ({ codeSnippet, isScanning }) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [codeSnippet]);

  return (
    <div className="bg-[#0c0c0c] border border-white/10 rounded-3xl overflow-hidden font-mono text-xs flex flex-col h-full shadow-2xl">
      {/* Terminal Header */}
      <div className="bg-[#1a1a1a] px-4 py-2 border-b border-white/5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal size={14} className="text-indigo-500" />
          <span className="text-slate-400 font-bold tracking-wider text-[10px] uppercase">Live Injection Stream</span>
        </div>
        <div className="flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-rose-500/20 border border-rose-500/50"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-amber-500/20 border border-amber-500/50"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/20 border border-emerald-500/50"></div>
        </div>
      </div>

      {/* Code Body */}
      <div className="flex-1 p-4 overflow-y-auto custom-scrollbar relative" ref={scrollRef}>
        {isScanning && (
          <div className="absolute top-0 left-0 w-full h-1 bg-indigo-500/50 shadow-[0_0_15px_#6366f1] animate-[scan_2s_ease-in-out_infinite]"></div>
        )}
        <pre className="text-slate-300 leading-relaxed whitespace-pre-wrap">
          {codeSnippet.split('\n').map((line, i) => (
            <div key={i} className={`flex ${line.includes('SCRIPT_INJECTION') || line.includes('HONEY') ? 'bg-rose-900/20 text-rose-400' : ''}`}>
               <span className="text-slate-700 w-8 text-right mr-4 select-none">{i + 1}</span>
               <span>{line}</span>
            </div>
          ))}
        </pre>
        {isScanning && (
          <div className="mt-2 text-indigo-400 animate-pulse">_ Awaiting new packets...</div>
        )}
      </div>
      
      <style>{`
        @keyframes scan {
          0% { top: 0%; opacity: 0.5; }
          50% { opacity: 1; }
          100% { top: 100%; opacity: 0.5; }
        }
      `}</style>
    </div>
  );
};

export default LiveCodeTerminal;
