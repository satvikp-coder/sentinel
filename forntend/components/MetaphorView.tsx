
import React, { useEffect, useRef } from 'react';

const MetaphorView: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let nodes: any[] = [];
    let agents: any[] = [];
    const width = canvas.width = canvas.parentElement?.clientWidth || 800;
    const height = canvas.height = 400;

    // Initialize City Nodes
    for (let i = 0; i < 30; i++) {
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        type: Math.random() > 0.8 ? 'MALICIOUS' : 'SAFE',
        pulse: Math.random() * Math.PI
      });
    }

    // Initialize Agents
    agents.push({ x: 50, y: height / 2, vx: 2, vy: 0.5 });

    const render = () => {
      ctx.fillStyle = '#020617';
      ctx.fillRect(0, 0, width, height);

      // Draw Grid
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
      ctx.lineWidth = 1;
      const gridSize = 40;
      for(let x=0; x<width; x+=gridSize) { ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,height); ctx.stroke(); }
      for(let y=0; y<height; y+=gridSize) { ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(width,y); ctx.stroke(); }

      // Draw Nodes
      nodes.forEach(node => {
        node.pulse += 0.05;
        const radius = 3 + Math.sin(node.pulse) * 1;
        
        ctx.beginPath();
        ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
        
        if (node.type === 'MALICIOUS') {
          ctx.fillStyle = '#f43f5e'; // Rose-500
          ctx.shadowBlur = 10;
          ctx.shadowColor = '#f43f5e';
        } else {
          ctx.fillStyle = '#3b82f6'; // Blue-500
          ctx.shadowBlur = 5;
          ctx.shadowColor = '#3b82f6';
        }
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      // Draw Shield (Security Layer)
      ctx.strokeStyle = '#6366f1'; // Indigo-500
      ctx.lineWidth = 2;
      ctx.setLineDash([5, 5]);
      ctx.beginPath();
      ctx.arc(width/2, height/2, 100, 0, Math.PI * 2);
      ctx.stroke();
      ctx.setLineDash([]);

      // Update and Draw Agents
      agents.forEach(agent => {
        agent.x += agent.vx;
        agent.y += agent.vy;

        // Bounce off walls
        if (agent.x > width || agent.x < 0) agent.vx *= -1;
        if (agent.y > height || agent.y < 0) agent.vy *= -1;

        // Draw Agent
        ctx.beginPath();
        ctx.arc(agent.x, agent.y, 6, 0, Math.PI * 2);
        ctx.fillStyle = '#10b981'; // Emerald-500
        ctx.fill();
        
        // Agent Trail
        ctx.beginPath();
        ctx.moveTo(agent.x - agent.vx * 10, agent.y - agent.vy * 10);
        ctx.lineTo(agent.x, agent.y);
        ctx.strokeStyle = 'rgba(16, 185, 129, 0.5)';
        ctx.lineWidth = 2;
        ctx.stroke();
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => cancelAnimationFrame(animationFrameId);
  }, []);

  return (
    <div className="w-full h-96 bg-slate-900 rounded-3xl border border-white/5 overflow-hidden relative shadow-2xl">
      <canvas ref={canvasRef} className="w-full h-full" />
      <div className="absolute bottom-4 left-4 bg-slate-950/80 px-4 py-2 rounded-xl border border-white/10 backdrop-blur-sm">
        <p className="text-[10px] font-black uppercase tracking-widest text-slate-400">Security Metaphor View</p>
        <div className="flex items-center gap-4 mt-2">
          <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-emerald-500"></div><span className="text-[10px] text-slate-300">Agent</span></div>
          <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-rose-500"></div><span className="text-[10px] text-slate-300">Threat</span></div>
          <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full border border-dashed border-indigo-500"></div><span className="text-[10px] text-slate-300">Policy Layer</span></div>
        </div>
      </div>
    </div>
  );
};

export default MetaphorView;
