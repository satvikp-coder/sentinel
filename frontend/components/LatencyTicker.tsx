
import React, { useState, useEffect } from 'react';
import { Activity } from 'lucide-react';

const LatencyTicker: React.FC = () => {
  const [latency, setLatency] = useState(12);
  
  // Simulate minor fluctuations
  useEffect(() => {
    const interval = setInterval(() => {
      setLatency(prev => {
        const variance = Math.floor(Math.random() * 5) - 2;
        return Math.max(8, Math.min(65, prev + variance));
      });
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  let color = 'text-emerald-500';
  let dotColor = 'bg-emerald-500';
  
  if (latency > 50) {
    color = 'text-rose-500';
    dotColor = 'bg-rose-500';
  } else if (latency > 20) {
    color = 'text-amber-500';
    dotColor = 'bg-amber-500';
  }

  return (
    <div className="flex items-center space-x-2 bg-black/40 px-3 py-1.5 rounded-lg border border-white/5 font-mono select-none">
      <div className={`w-1.5 h-1.5 rounded-full ${dotColor} animate-pulse`}></div>
      <span className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">Security Overhead:</span>
      <span className={`text-xs font-bold ${color}`}>+{latency}ms</span>
    </div>
  );
};

export default LatencyTicker;
