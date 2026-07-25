import { createContext, useContext, useState, useCallback, type PropsWithChildren } from 'react';

interface ToastItem {
  id: number;
  message: string;
  type: 'success' | 'error' | 'info';
}

interface ConfirmState {
  message: string;
  resolve: (ok: boolean) => void;
}

interface ToastContextValue {
  toast: (message: string, type?: 'success' | 'error' | 'info') => void;
  confirm: (message: string) => Promise<boolean>;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
}

export function ToastProvider({ children }: PropsWithChildren) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [confirmState, setConfirmState] = useState<ConfirmState | null>(null);

  const toast = useCallback((message: string, type: 'success' | 'error' | 'info' = 'success') => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 3000);
  }, []);

  const confirm = useCallback((message: string): Promise<boolean> => {
    return new Promise<boolean>(resolve => {
      setConfirmState({ message, resolve });
    });
  }, []);

  return (
    <ToastContext.Provider value={{ toast, confirm }}>
      {children}
      {/* Toast container */}
      <div className="toast-container">
        {toasts.map(t => (
          <div key={t.id} className={`toast toast-${t.type}`}>
            {t.message}
          </div>
        ))}
      </div>
      {/* Confirm dialog */}
      {confirmState && (
        <div className="confirm-overlay" onClick={() => { confirmState.resolve(false); setConfirmState(null); }}>
          <div className="confirm-dialog" onClick={e => e.stopPropagation()}>
            <p className="confirm-message">{confirmState.message}</p>
            <div className="split" style={{ justifyContent: 'flex-end', gap: 8 }}>
              <button className="btn" onClick={() => { confirmState.resolve(false); setConfirmState(null); }}>取消</button>
              <button className="btn primary" onClick={() => { confirmState.resolve(true); setConfirmState(null); }}>确认</button>
            </div>
          </div>
        </div>
      )}
    </ToastContext.Provider>
  );
}
