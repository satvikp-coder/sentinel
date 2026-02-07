
import React from 'react';
import { EyeOff, AlertTriangle } from 'lucide-react';

interface EnvironmentAlertProps {
  type: 'IFRAME' | 'CANVAS' | 'ENCRYPTED';
}

const EnvironmentAlert: React.FC<EnvironmentAlertProps> = ({ type }) => {
  const config = {
    IFRAME: {
      label: 'Cross-Origin Iframe Detected',
      desc: 'Content within external frames cannot be fully inspected by DOM analysis.',
      color: 'text-amber-500',
      border: 'border-amber-500/20',
      bg: 'bg-amber-500/5'
    },
    CANVAS: {
      label: 'Canvas Rendering Detected',
      desc: 'Visual elements rendered via WebGL/Canvas are opaque to semantic analysis.',
      color: 'text-purple-400',
      border: 'border-purple-500/20',
      bg: 'bg-purple-500/5'
    },
    ENCRYPTED: {
      label: 'Encrypted Media Extensions',
      desc: 'DRM-protected content stream detected. Visual analysis disabled.',
      color: 'text-slate-400',
      border: 'border-slate-500/20',
      bg: 'bg-slate-500/5'
    }
  }[type];

  return (
    <div className={`flex items-start gap-3 p-3 rounded-lg border ${config.border} ${config.bg} mb-4 animate-in fade-in slide-in-from-top-2`}>
      <EyeOff size={16} className={`mt-0.5 ${config.color}`} />
      <div>
        <h4 className={`text-[10px] font-black uppercase tracking-widest ${config.color}`}>
          Blind Spot Warning: {config.label}
        </h4>
        <p className="text-[10px] text-slate-400 mt-1 leading-relaxed max-w-xs">
          {config.desc}
        </p>
      </div>
    </div>
  );
};

export default EnvironmentAlert;
