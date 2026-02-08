import React, { useEffect, useState } from 'react';
import { Shield } from 'lucide-react';

interface SplashScreenProps {
  onComplete: () => void;
}

const SplashScreen: React.FC<SplashScreenProps> = ({ onComplete }) => {
  const [text, setText] = useState('');
  const [opacity, setOpacity] = useState(100);
  
  // Using SENTINEL to match app name, but applying the requested IDTRUST style logic
  const finalText = "SENTINEL"; 
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#%&@$*^!";

  useEffect(() => {
    let iteration = 0;
    let interval: any = null;

    // Glitch Text Logic
    interval = setInterval(() => {
      setText(prev => 
        finalText
          .split("")
          .map((letter, index) => {
            if (index < iteration) {
              return finalText[index];
            }
            return chars[Math.floor(Math.random() * chars.length)];
          })
          .join("")
      );

      if (iteration >= finalText.length) {
        clearInterval(interval);
      }

      iteration += 1 / 3; 
    }, 40);

    // Transition Sequence
    const timeout = setTimeout(() => {
      setOpacity(0);
      setTimeout(onComplete, 700); // Wait for fade out transition (700ms)
    }, 3200);

    return () => {
      clearInterval(interval);
      clearTimeout(timeout);
    };
  }, [onComplete]);

  if (opacity === 0) return null;

  return (
    <div 
      className="fixed inset-0 z-[100] bg-[#020617] flex items-center justify-center transition-opacity duration-700 ease-out overflow-hidden"
      style={{ opacity: opacity / 100 }}
    >
      {/* Moving Background Grid */}
      <div className="absolute inset-0 z-0 opacity-20 pointer-events-none animate-[moveGrid_20s_linear_infinite]" 
        style={{
          backgroundImage: `linear-gradient(rgba(99, 102, 241, 0.1) 1px, transparent 1px),
          linear-gradient(90deg, rgba(99, 102, 241, 0.1) 1px, transparent 1px)`,
          backgroundSize: '60px 60px',
        }}
      ></div>

      {/* Cyber Corner Brackets */}
      <div className="absolute top-12 left-12 w-24 h-24 border-l-4 border-t-4 border-indigo-500/30 rounded-tl-3xl"></div>
      <div className="absolute top-12 right-12 w-24 h-24 border-r-4 border-t-4 border-indigo-500/30 rounded-tr-3xl"></div>
      <div className="absolute bottom-12 left-12 w-24 h-24 border-l-4 border-b-4 border-indigo-500/30 rounded-bl-3xl"></div>
      <div className="absolute bottom-12 right-12 w-24 h-24 border-r-4 border-b-4 border-indigo-500/30 rounded-br-3xl"></div>

      {/* Main Content */}
      <div className="relative z-10 flex flex-col items-center">
        {/* Pulsing Shield Logo */}
        <div className="relative mb-10">
          <div className="absolute inset-0 bg-indigo-500 blur-3xl opacity-20 animate-pulse rounded-full"></div>
          <Shield size={96} className="text-indigo-500 relative z-10 animate-pulse drop-shadow-[0_0_15px_rgba(99,102,241,0.5)]" strokeWidth={1.5} />
          <div className="absolute inset-0 border-2 border-indigo-400/30 rounded-full animate-ping opacity-20"></div>
          <div className="absolute inset-[-20%] border border-indigo-500/10 rounded-full animate-[spin_10s_linear_infinite]"></div>
        </div>

        {/* Glitch Title */}
        <div className="relative">
          <h1 className="text-7xl font-black text-white tracking-[0.25em] font-mono relative z-10 pl-4">
            {text}
          </h1>
          {/* Laser Scan Line */}
          <div className="absolute top-0 left-0 w-full h-full pointer-events-none overflow-hidden z-20">
             <div className="w-full h-0.5 bg-indigo-400 shadow-[0_0_20px_#818cf8] absolute top-[-100%] animate-[scan_2.5s_ease-in-out_infinite]"></div>
          </div>
        </div>
        
        {/* Loading Indicator */}
        <div className="mt-8 flex items-center space-x-3 bg-indigo-950/30 px-4 py-2 rounded-full border border-indigo-500/10 backdrop-blur-sm">
             <div className="h-1.5 w-1.5 bg-emerald-500 rounded-full animate-[ping_1.5s_cubic-bezier(0,0,0.2,1)_infinite]"></div>
             <span className="text-indigo-300 font-mono text-[10px] tracking-[0.2em] uppercase font-bold">Initializing Secure Environment...</span>
        </div>
      </div>

      <style>{`
        @keyframes scan {
          0% { top: -20%; opacity: 0; }
          20% { opacity: 1; }
          80% { opacity: 1; }
          100% { top: 120%; opacity: 0; }
        }
        @keyframes moveGrid {
          0% { background-position: 0 0; }
          100% { background-position: 60px 60px; }
        }
      `}</style>
    </div>
  );
};

export default SplashScreen;