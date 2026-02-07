
import React, { useState } from 'react';
import { Sliders, Save, RefreshCw, AlertTriangle, Shield, CheckCircle, Code } from 'lucide-react';
import { PolicyConfig } from '../types';

const PolicySandbox: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'VISUAL' | 'JSON'>('VISUAL');
  const [config, setConfig] = useState<PolicyConfig>({
    promptInjectionWeight: 80,
    hiddenContentWeight: 60,
    deceptiveUiWeight: 90,
    strictMode: true
  });

  const [jsonConfig, setJsonConfig] = useState(JSON.stringify(config, null, 2));

  const handleJsonChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setJsonConfig(e.target.value);
    try {
      const parsed = JSON.parse(e.target.value);
      setConfig(parsed);
    } catch (err) {
      // Invalid JSON, ignore update
    }
  };

  return (
    <div className="max-w-6xl mx-auto pt-6 pb-12">
      <div className="flex items-end justify-between mb-8">
        <div>
          <h1 className="text-4xl font-black text-white uppercase tracking-tighter mb-2">Policy Sandbox</h1>
          <p className="text-sm text-slate-400 font-mono">Experiment with detection weights and simulate risk impact in real-time.</p>
        </div>
        <button className="flex items-center space-x-2 bg-indigo-600 text-white px-6 py-3 rounded-xl font-bold uppercase tracking-wider text-xs shadow-[0_0_20px_rgba(79,70,229,0.3)] hover:bg-indigo-500 transition-all">
          <Save size={16} />
          <span>Deploy Policy</span>
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-4 mb-8">
        <button
          onClick={() => setActiveTab('VISUAL')}
          className={`px-6 py-2 rounded-lg font-bold uppercase text-xs tracking-wider transition-all ${activeTab === 'VISUAL' ? 'bg-white text-black' : 'bg-slate-900 text-slate-500 border border-white/5'}`}
        >
          Visual Controls
        </button>
        <button
          onClick={() => setActiveTab('JSON')}
          className={`px-6 py-2 rounded-lg font-bold uppercase text-xs tracking-wider transition-all flex items-center gap-2 ${activeTab === 'JSON' ? 'bg-white text-black' : 'bg-slate-900 text-slate-500 border border-white/5'}`}
        >
          <Code size={14} /> Policy-as-Code
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">

        {/* Controls Column */}
        <div className="lg:col-span-2 space-y-6">
          {activeTab === 'VISUAL' ? (
            <>
              <div className="bg-slate-900 border border-white/5 rounded-3xl p-8 shadow-xl">
                <div className="flex items-center justify-between mb-8">
                  <h3 className="text-sm font-black text-white uppercase tracking-widest flex items-center gap-2">
                    <Sliders size={16} className="text-indigo-400" /> Detection Weights
                  </h3>
                  <span className="text-[10px] text-slate-500 font-mono">ADJUST SENSITIVITY</span>
                </div>

                <div className="space-y-8">
                  <WeightSlider
                    label="Prompt Injection Sensitivity"
                    value={config.promptInjectionWeight}
                    onChange={(v) => { setConfig({ ...config, promptInjectionWeight: v }); setJsonConfig(JSON.stringify({ ...config, promptInjectionWeight: v }, null, 2)); }}
                    color="text-rose-400"
                  />
                  <WeightSlider
                    label="Hidden Content Detection"
                    value={config.hiddenContentWeight}
                    onChange={(v) => { setConfig({ ...config, hiddenContentWeight: v }); setJsonConfig(JSON.stringify({ ...config, hiddenContentWeight: v }, null, 2)); }}
                    color="text-amber-400"
                  />
                  <WeightSlider
                    label="Deceptive UI Analysis"
                    value={config.deceptiveUiWeight}
                    onChange={(v) => { setConfig({ ...config, deceptiveUiWeight: v }); setJsonConfig(JSON.stringify({ ...config, deceptiveUiWeight: v }, null, 2)); }}
                    color="text-emerald-400"
                  />
                </div>
              </div>

              <div className="bg-slate-900 border border-white/5 rounded-3xl p-8 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-black text-white uppercase tracking-widest">Strict Enforcement Mode</h3>
                  <p className="text-xs text-slate-500 mt-1 font-mono">Automatically block any action with Risk Score &gt; 75.</p>
                </div>
                <div
                  onClick={() => { setConfig({ ...config, strictMode: !config.strictMode }); setJsonConfig(JSON.stringify({ ...config, strictMode: !config.strictMode }, null, 2)); }}
                  className={`w-14 h-8 rounded-full p-1 cursor-pointer transition-colors duration-300 ${config.strictMode ? 'bg-indigo-600' : 'bg-slate-700'}`}
                >
                  <div className={`w-6 h-6 rounded-full bg-white shadow-md transform transition-transform duration-300 ${config.strictMode ? 'translate-x-6' : 'translate-x-0'}`}></div>
                </div>
              </div>
            </>
          ) : (
            <div className="bg-slate-900 border border-white/5 rounded-3xl p-0 overflow-hidden h-full flex flex-col">
              <div className="bg-[#1e1e1e] p-2 border-b border-white/5 flex gap-2">
                <div className="w-3 h-3 rounded-full bg-rose-500/20"></div>
                <div className="w-3 h-3 rounded-full bg-amber-500/20"></div>
                <div className="w-3 h-3 rounded-full bg-emerald-500/20"></div>
                <span className="text-[10px] text-slate-500 font-mono ml-2">policy_config.json</span>
              </div>
              <textarea
                value={jsonConfig}
                onChange={handleJsonChange}
                className="w-full h-96 bg-[#1e1e1e] text-indigo-300 font-mono p-6 text-sm focus:outline-none resize-none leading-relaxed"
                spellCheck="false"
              />
              <div className="bg-[#1e1e1e] px-4 py-2 border-t border-white/5 text-[10px] text-slate-500 font-mono flex justify-between">
                <span>JSON Mode: Valid</span>
                <span>Ln 12, Col 4</span>
              </div>
            </div>
          )}
        </div>

        {/* Simulation Preview */}
        <div className="bg-gradient-to-b from-slate-900 to-indigo-950/20 border border-white/5 rounded-3xl p-8 flex flex-col">
          <h3 className="text-sm font-black text-white uppercase tracking-widest mb-6 flex items-center gap-2">
            <RefreshCw size={16} className="text-indigo-400" /> Simulated Impact
          </h3>

          <div className="flex-1 flex flex-col justify-center items-center text-center space-y-6">
            <div className="relative">
              <Shield size={64} className={`transition-colors duration-500 ${config.strictMode ? 'text-emerald-500' : 'text-amber-500'}`} />
              <div className={`absolute -top-2 -right-2 w-6 h-6 rounded-full flex items-center justify-center border-2 border-slate-900 text-[10px] font-bold ${config.strictMode ? 'bg-emerald-500 text-slate-900' : 'bg-amber-500 text-slate-900'}`}>
                {config.strictMode ? 'S' : 'L'}
              </div>
            </div>

            <div>
              <div className="text-3xl font-black text-white tracking-tighter">
                {Math.round((config.promptInjectionWeight + config.deceptiveUiWeight + config.hiddenContentWeight) / 3)}%
              </div>
              <div className="text-[10px] text-slate-500 uppercase font-black tracking-widest mt-1">Projected Block Rate</div>
            </div>

            <div className="w-full bg-slate-950 rounded-xl p-4 text-left space-y-3 border border-white/5">
              <div className="flex justify-between text-xs">
                <span className="text-slate-400">False Positives</span>
                <span className="text-rose-400 font-mono font-bold">~1.2%</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-400">Missed Threats</span>
                <span className="text-emerald-400 font-mono font-bold">~0.05%</span>
              </div>
            </div>
          </div>

          {!config.strictMode && (
            <div className="mt-6 flex items-start space-x-3 p-4 bg-amber-500/10 rounded-xl border border-amber-500/20">
              <AlertTriangle size={16} className="text-amber-500 shrink-0 mt-0.5" />
              <p className="text-[10px] text-amber-200/80 leading-relaxed">
                <strong className="text-amber-500">Warning:</strong> Lenient mode may allow sophisticated prompt injections to bypass the filter.
              </p>
            </div>
          )}
        </div>

      </div>
    </div>
  );
};

const WeightSlider = ({ label, value, onChange, color }: { label: string, value: number, onChange: (v: number) => void, color: string }) => (
  <div className="space-y-3">
    <div className="flex justify-between items-end">
      <label className="text-xs font-bold text-slate-300 uppercase tracking-wider">{label}</label>
      <span className={`font-mono text-sm font-bold ${color}`}>{value}%</span>
    </div>
    <input
      type="range"
      min="0"
      max="100"
      value={value}
      onChange={(e) => onChange(parseInt(e.target.value))}
      className="w-full h-2 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-indigo-500 hover:accent-indigo-400 transition-all"
    />
  </div>
);

export default PolicySandbox;
