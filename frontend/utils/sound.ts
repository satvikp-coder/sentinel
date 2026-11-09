
// Synthesized Sound Effects for Sentinel
// Uses Web Audio API to generate UI sounds without external assets

const AudioContextClass = (window.AudioContext || (window as any).webkitAudioContext);
let audioCtx: AudioContext | null = null;
let isMuted = false;

const initAudio = () => {
  if (!audioCtx) {
    audioCtx = new AudioContextClass();
  }
};

export const toggleMute = () => {
  isMuted = !isMuted;
  return isMuted;
};

const playTone = (freq: number, type: OscillatorType, duration: number, vol: number = 0.1) => {
  if (isMuted) return;
  initAudio();
  if (!audioCtx) return;

  const osc = audioCtx.createOscillator();
  const gain = audioCtx.createGain();

  osc.type = type;
  osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
  
  gain.gain.setValueAtTime(vol, audioCtx.currentTime);
  gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + duration);

  osc.connect(gain);
  gain.connect(audioCtx.destination);

  osc.start();
  osc.stop(audioCtx.currentTime + duration);
};

export const playSound = (type: 'PING' | 'BLOCK' | 'ALARM' | 'CLICK' | 'HOVER') => {
  switch (type) {
    case 'PING': // Threat Detected
      playTone(880, 'sine', 0.1, 0.1);
      setTimeout(() => playTone(1760, 'sine', 0.2, 0.1), 100);
      break;
    case 'BLOCK': // Action Blocked
      playTone(150, 'square', 0.3, 0.15);
      break;
    case 'ALARM': // Honey Pot / Critical
      playTone(440, 'sawtooth', 0.1, 0.1);
      setTimeout(() => playTone(440, 'sawtooth', 0.1, 0.1), 150);
      setTimeout(() => playTone(440, 'sawtooth', 0.1, 0.1), 300);
      break;
    case 'CLICK': // UI Interaction
      playTone(1200, 'triangle', 0.05, 0.05);
      break;
    case 'HOVER': // Subtle UI Hover
      playTone(400, 'sine', 0.03, 0.02);
      break;
  }
};
