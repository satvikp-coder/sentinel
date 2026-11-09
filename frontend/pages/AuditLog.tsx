
import React from 'react';
import { MOCK_AUDIT_LOGS } from '../services/mockData';
import { FileText, Shield, AlertCircle, CheckCircle } from 'lucide-react';

const AuditLog: React.FC = () => {
  return (
    <div className="max-w-6xl mx-auto pt-6">
      <div className="flex items-end justify-between mb-8">
        <div>
          <h1 className="text-4xl font-black text-white uppercase tracking-tighter mb-2">Immutable Audit Log</h1>
          <p className="text-sm text-slate-400 font-mono">Traceable history of all agent activities and human interventions.</p>
        </div>
        <div className="flex items-center space-x-2 px-4 py-2 bg-slate-900 rounded-lg border border-white/5">
           <Shield size={14} className="text-emerald-500" />
           <span className="text-[10px] font-bold text-emerald-500 uppercase tracking-wider">Blockchain Verified</span>
        </div>
      </div>

      <div className="bg-slate-900 border border-white/5 rounded-3xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-white/5 bg-slate-950/50">
                <th className="p-6 text-[10px] font-black text-slate-500 uppercase tracking-widest">Timestamp</th>
                <th className="p-6 text-[10px] font-black text-slate-500 uppercase tracking-widest">User / Agent</th>
                <th className="p-6 text-[10px] font-black text-slate-500 uppercase tracking-widest">Action</th>
                <th className="p-6 text-[10px] font-black text-slate-500 uppercase tracking-widest">Target</th>
                <th className="p-6 text-[10px] font-black text-slate-500 uppercase tracking-widest">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {MOCK_AUDIT_LOGS.map((log) => (
                <tr key={log.id} className="hover:bg-white/5 transition-colors group">
                  <td className="p-6 text-xs font-mono text-slate-400">{log.timestamp}</td>
                  <td className="p-6">
                    <div className="flex items-center gap-2">
                       <div className="w-6 h-6 rounded bg-slate-800 flex items-center justify-center text-[10px] font-bold text-slate-300">
                         {log.userId.substring(0, 2).toUpperCase()}
                       </div>
                       <span className="text-xs font-bold text-slate-200">{log.userId}</span>
                    </div>
                  </td>
                  <td className="p-6">
                    <span className="text-xs font-bold text-white bg-slate-800 px-2 py-1 rounded border border-white/5">
                      {log.action}
                    </span>
                    <p className="text-[10px] text-slate-500 mt-1">{log.reason}</p>
                  </td>
                  <td className="p-6 text-xs font-mono text-indigo-300">{log.target}</td>
                  <td className="p-6">
                    <div className="flex items-center gap-2">
                      {log.status === 'SUCCESS' && <CheckCircle size={14} className="text-emerald-500" />}
                      {log.status === 'WARNING' && <AlertCircle size={14} className="text-amber-500" />}
                      {log.status === 'FAILURE' && <AlertCircle size={14} className="text-rose-500" />}
                      <span className={`text-[10px] font-black uppercase tracking-wider ${
                        log.status === 'SUCCESS' ? 'text-emerald-500' : 
                        log.status === 'WARNING' ? 'text-amber-500' : 'text-rose-500'
                      }`}>
                        {log.status}
                      </span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default AuditLog;
