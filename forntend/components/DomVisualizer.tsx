
import React from 'react';
import { DomNode, ThreatType } from '../types';
import { AlertOctagon, EyeOff, MousePointerClick, Code, Zap, Hexagon, Layers } from 'lucide-react';
import { playSound } from '../utils/sound';

interface DomVisualizerProps {
  node: DomNode;
  highlightedNodeId?: string;
  onNodeClick: (node: DomNode) => void;
  depth?: number;
}

const ThreatIcon = ({ type }: { type?: ThreatType }) => {
  switch (type) {
    case ThreatType.PROMPT_INJECTION: return <Code size={12} className="text-rose-500" />;
    case ThreatType.HIDDEN_CONTENT: return <EyeOff size={12} className="text-orange-500" />;
    case ThreatType.DECEPTIVE_UI: return <MousePointerClick size={12} className="text-rose-500" />;
    case ThreatType.HONEY_PROMPT_TRIGGER: return <Hexagon size={12} className="text-amber-500" />;
    default: return null;
  }
};

const DomVisualizer: React.FC<DomVisualizerProps> = ({ node, highlightedNodeId, onNodeClick, depth = 0 }) => {
  const isHighlighted = highlightedNodeId === node.id;
  const isFlagged = node.isFlagged;
  const isHoneyPot = node.isHoneyPot;
  const isShadowRoot = node.isShadowRoot;

  let bgClass = 'bg-transparent hover:bg-white/5 border-transparent';
  let borderClass = 'border border-white/0';
  let textClass = 'text-indigo-300';
  let containerClass = 'relative mb-1 p-2 rounded-lg cursor-pointer transition-all duration-200 flex items-center space-x-2';
  
  if (isHighlighted) {
    bgClass = 'bg-indigo-500/20 border-indigo-500/50 shadow-[0_0_15px_rgba(99,102,241,0.15)]';
  } else if (isHoneyPot) {
    bgClass = 'bg-amber-500/10 border-amber-500/30';
    borderClass = 'border-l-2 border-amber-500';
    textClass = 'text-amber-400';
  } else if (isShadowRoot) {
    bgClass = 'bg-purple-500/10 border-purple-500/30';
    borderClass = 'border-l-2 border-purple-500';
    textClass = 'text-purple-400';
  } else if (isFlagged) {
    bgClass = 'bg-rose-900/10 border-rose-500/30';
    borderClass = 'border-l-2 border-rose-500';
    textClass = 'text-rose-400 glitch-text'; // Added glitch effect
    containerClass += ' overflow-hidden';
  }

  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation(); 
    onNodeClick(node);
    playSound('CLICK');
  };

  return (
    <div className="font-mono text-sm select-none">
      <div 
        onClick={handleClick}
        style={{ marginLeft: `${depth * 16}px` }}
        className={`${containerClass} ${bgClass} ${borderClass}`}
      >
        <span className="text-slate-600 text-xs">&lt;</span>
        <span className={`font-bold ${textClass}`} data-text={node.tag}>
          {node.tag}
        </span>
        {node.attributes?.id && <span className="text-sky-400 text-xs">#{node.attributes.id}</span>}
        
        {isHoneyPot && (
           <div className="ml-auto flex items-center space-x-2 px-2 py-0.5 bg-amber-500/20 rounded-md border border-amber-500/30">
             <Hexagon size={12} className="text-amber-500" />
             <span className="text-[10px] font-black text-amber-400 uppercase tracking-wider">HONEY-POT</span>
           </div>
        )}

        {isShadowRoot && (
           <div className="ml-auto flex items-center space-x-2 px-2 py-0.5 bg-purple-500/20 rounded-md border border-purple-500/30">
             <Layers size={12} className="text-purple-500" />
             <span className="text-[10px] font-black text-purple-400 uppercase tracking-wider">SHADOW DOM</span>
           </div>
        )}

        {isFlagged && !isHoneyPot && (
           <div className="ml-auto flex items-center space-x-2 px-2 py-0.5 bg-rose-500/20 rounded-md border border-rose-500/30 animate-pulse">
             <ThreatIcon type={node.threatType} />
             <span className="text-[10px] font-black text-rose-400 uppercase tracking-wider">{node.threatType}</span>
           </div>
        )}
        
        <span className="text-slate-600 text-xs">&gt;</span>
        
        {node.content && (
          <span className="ml-2 text-slate-400 truncate max-w-[200px] italic">
            "{node.content}"
          </span>
        )}
      </div>

      {node.children && node.children.map(child => (
        <DomVisualizer 
          key={child.id} 
          node={child} 
          highlightedNodeId={highlightedNodeId}
          onNodeClick={onNodeClick}
          depth={depth + 1} 
        />
      ))}
    </div>
  );
};

export default DomVisualizer;
