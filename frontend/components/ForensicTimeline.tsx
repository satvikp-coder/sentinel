
import React, { useState, useEffect } from 'react';
import { ForensicSnapshot, ThreatType } from '../types';
import { Play, Pause, ChevronLeft, ChevronRight, AlertTriangle } from 'lucide-react';

interface ForensicTimelineProps {
  snapshots: ForensicSnapshot[];
  currentSnapshot: ForensicSnapshot | null;
  onScrub: (timestamp: number) => void;
}

const ForensicTimeline: React.FC<ForensicTimelineProps> = ({ snapshots, currentSnapshot, onScrub }) => {
  const [isPlaying, setIsPlaying] = useState(false);

  useEffect(() => {
    let interval: any;
    if (isPlaying) {
      interval = setInterval(() => {
        // Find next snapshot
        if (!currentSnapshot) return;
        const currentIndex = snapshots.findIndex(s => s.timestamp === currentSnapshot.timestamp);
        if (currentIndex < snapshots.length - 1) {
          onScrub(snapshots[currentIndex + 1].timestamp);
        } else {
          setIsPlaying(false);
        }
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [isPlaying, currentSnapshot, snapshots, onScrub]);

  if (!snapshots.length) return null;

  const startTime = snapshots[0].timestamp;
  const endTime = snapshots[snapshots.length - 1].timestamp;
  const duration = endTime - startTime;

  return (
    <div className="bg-slate-900 border-t border-white/10 p-4 h-32 flex flex-col justify-between">
      <div className="flex items-center justify-between mb-2">
         <h4 className="text-[10px] font-black uppercase tracking-widest text-slate-500 flex items-center gap-2">
           <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
           Forensic Time-Travel
         </h4>
         <div className="flex gap-2">
            <button 
              onClick={() => setIsPlaying(!isPlaying)}
              className="w-8 h-8 rounded-full bg-slate-800 border border-white/10 flex items-center justify-center hover:bg-indigo-600 hover:text-white transition-all"
            >
              {isPlaying ? <Pause size={12} /> : <Play size={12} />}
            </button>
         </div>
      </div>

      <div className="relative h-12 bg-black/50 rounded-lg border border-white/5 mb-1 group cursor-pointer">
        {/* Threat Markers */}
        {snapshots.map((snap) => {
          const position = ((snap.timestamp - startTime) / duration) * 100;
          const hasThreat = snap.activeThreats.length > 0;
          if (!hasThreat) return null;

          return (
            <div 
              key={snap.timestamp}
              className="absolute top-0 bottom-0 w-0.5 bg-rose-500/50 z-10"
              style={{ left: `${position}%` }}
              title={`Threat Detected: ${snap.activeThreats.join(', ')}`}
            >
              <div className="absolute top-0 -translate-x-1/2 -translate-y-full">
                 <AlertTriangle size={10} className="text-rose-500" />
              </div>
            </div>
          );
        })}

        {/* Scrubber Head */}
        {currentSnapshot && (
          <div 
            className="absolute top-0 bottom-0 w-0.5 bg-indigo-500 z-20 transition-all duration-300 ease-linear"
            style={{ left: `${((currentSnapshot.timestamp - startTime) / duration) * 100}%` }}
          >
            <div className="absolute top-1/2 -translate-x-1/2 -translate-y-1/2 w-3 h-3 bg-indigo-500 rounded-full shadow-[0_0_10px_#6366f1]"></div>
          </div>
        )}
        
        {/* Click Area */}
        <input 
          type="range" 
          min={startTime} 
          max={endTime} 
          value={currentSnapshot?.timestamp || startTime}
          onChange={(e) => onScrub(parseInt(e.target.value))}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-30"
        />
      </div>

      <div className="flex justify-between text-[10px] font-mono text-slate-600">
         <span>00:00:00</span>
         <span>{new Date(duration).toISOString().substr(11, 8)}</span>
      </div>
    </div>
  );
};

export default ForensicTimeline;
