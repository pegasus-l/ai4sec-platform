import { Moon, Sun } from 'lucide-react';
import { useEffect, useState } from 'react';

export function ThemeToggle() {
  const [dark, setDark] = useState(false);
  useEffect(() => {
    const saved = window.localStorage.getItem('ai_security_radar_theme');
    const nextDark = saved ? saved === 'dark' : true;
    setDark(nextDark);
    document.documentElement.classList.toggle('dark', nextDark);
    document.documentElement.classList.toggle('light', !nextDark);
  }, []);
  function toggle() {
    const nextDark = !dark;
    setDark(nextDark);
    document.documentElement.classList.toggle('dark', nextDark);
    document.documentElement.classList.toggle('light', !nextDark);
    window.localStorage.setItem('ai_security_radar_theme', nextDark ? 'dark' : 'light');
  }
  return (
    <button type='button' onClick={toggle} title={dark ? '切换浅色主题' : '切换深色主题'} className='theme-toggle focus-ring'>
      {dark ? <Sun size={17} /> : <Moon size={17} />}
    </button>
  );
}
