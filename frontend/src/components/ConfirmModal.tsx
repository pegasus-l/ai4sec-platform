import { useEffect, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

export interface ConfirmRequest {
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** 危险操作(清理/删除): 确认按钮染红 */
  danger?: boolean;
  onConfirm: () => void | Promise<void>;
}

/**
 * 二次确认弹窗。
 *
 * 为什么不用 window.confirm: 页面可能被嵌在 iframe 里(洞察嵌入第三方系统), 浏览器在跨源
 * iframe 中会直接吞掉 alert/confirm/prompt —— 点了「清理」既不弹窗也不执行, 看起来就是
 * 「没反应」。自带弹窗走 DOM, 不受这个限制。
 *
 * 样式复用「添加案例」弹窗那一套(.modal-mask / .modal-card), 只多一个 .confirm-card 收窄宽度。
 */
export function ConfirmModal({ request, onClose }: { request: ConfirmRequest | null; onClose: () => void }) {
  const [busy, setBusy] = useState(false);
  const okRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!request) return;
    setBusy(false);
    // 焦点落在确认按钮: 键盘可达, 且不会因为焦点在页面上而把 Esc 吃掉
    okRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [request, onClose]);

  if (!request) return null;

  const run = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await request.onConfirm();
      onClose();
    } finally {
      setBusy(false);
    }
  };

  return createPortal(
    <div className="modal-mask" onClick={() => { if (!busy) onClose(); }}>
      <div
        className="modal-card confirm-card"
        role="dialog"
        aria-modal="true"
        aria-label={request.title}
        onClick={e => e.stopPropagation()}
      >
        <div className="modal-head"><h3>{request.title}</h3></div>
        <div className="modal-body">
          <div className="confirm-body">{request.message}</div>
          <div className="confirm-actions">
            <button className="btn" onClick={onClose} disabled={busy}>{request.cancelLabel ?? '取消'}</button>
            <button ref={okRef} className={`btn ${request.danger ? 'danger' : 'primary'}`} onClick={run} disabled={busy}>
              {busy ? '处理中…' : (request.confirmLabel ?? '确认')}
            </button>
          </div>
        </div>
      </div>
    </div>,
    document.body,
  );
}
