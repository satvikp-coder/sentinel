
import React, { createContext, useContext, useState, useCallback } from 'react';
import { CheckCircle, AlertCircle, Info, X } from 'lucide-react';
import { playSound } from '../utils/sound';

type ToastType = 'SUCCESS' | 'ERROR' | 'INFO';

interface Toast {
  id: string;
  message: string;
  type: ToastType;
}

interface ToastContextType {
  showToast: (message: string, type: ToastType) => void;
}

const ToastContext = createContext<ToastContextType | undefined>(undefined);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const showToast = useCallback((message: string, type: ToastType) => {
    const id = Math.random().toString(36).substr(2, 9);
    setToasts((prev) => [...prev, { id, message, type }]);
    
    // Audio Cue
    if (type === 'SUCCESS') playSound('CLICK');
    if (type === 'ERROR') playSound('BLOCK');

    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3000);
  }, []);

  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-[100] flex flex-col gap-2 pointer-events-none">
        {toasts.map((toast) => (
          <div 
            key={toast.id}
            className="animate-in slide-in-from-bottom-5 fade-in duration-300 pointer-events-auto min-w-[300px] flex items-center gap-3 px-4 py-3 rounded-xl bg-slate-900/90 backdrop-blur border border-white/10 shadow-2xl"
          >
            {toast.type === 'SUCCESS' && <CheckCircle size={16} className="text-emerald-500" />}
            {toast.type === 'ERROR' && <AlertCircle size={16} className="text-rose-500" />}
            {toast.type === 'INFO' && <Info size={16} className="text-indigo-500" />}
            <span className="text-xs font-bold text-white tracking-wide">{toast.message}</span>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
};

export const useToast = () => {
  const context = useContext(ToastContext);
  if (!context) throw new Error('useToast must be used within a ToastProvider');
  return context;
};
