import { useEffect, useState } from 'react';
import { AlertTriangle } from 'lucide-react';
import { AUTH_REQUIRED_EVENT, loginUrl, type AuthNoticeKind } from '../api/client';

/**
 * 登录问题横幅(过期 / 只读会话)。
 *
 * 为什么需要它: 能力洞察挂在入口网关(136 radar)的 `/insights` 前缀下, 而 `/insights/*`
 * 在那台 nginx 里是**直转隧道**的 —— 绕过了 radar 自己的会话校验。于是 cookie 过期后:
 * 页面(SPA)照旧返回 200、只有每个 `/api/*` 报错, 用户看到的是"空页面 + 没有任何提示
 * + 不跳登录页"。后端现在会对"浏览器导航"补 307 跳转(见 middleware.py); 这个组件负责
 * 处理**不打导航**的那些请求 —— SPA 内部切域、复现状态每 5s 的轮询 —— 在页面原地给出口。
 *
 * 2026-10-31 补第三种: 会话过期时后端会静默回退到网关的嵌入票(viewer), 写操作于是返回
 * **403 而不是 401**。以前这里只认 401, 用户点「项目复现」看到的是"403"且毫无提示。
 * 现在按后端给的 reason 分三档, 让用户知道"重登一下就好"还是"这账号本来就只读"。
 *
 * 不做自动跳转: 过期时用户可能正在看复现日志, 直接把人踢走会丢掉现场; 由用户点"重新登录"
 * 决定, 回跳地址就是当前这一页(client.ts 的 loginUrl)。
 */
const MESSAGES: Record<AuthNoticeKind, string> = {
  expired: '登录已过期，页面数据已停止更新。',
  readonly_login: '登录已失效，当前为只读访问，登录后可执行此操作。',
  readonly_account: '当前账号为只读，无法执行此操作。',
};

/** 账号本身就是只读时, 重新登录没有意义, 不给登录入口。 */
const ACTION_LABEL: Record<AuthNoticeKind, string | null> = {
  expired: '重新登录',
  readonly_login: '重新登录',
  readonly_account: null,
};

export function AuthExpiredBanner() {
  const [kind, setKind] = useState<AuthNoticeKind | null>(null);

  useEffect(() => {
    const onAuthRequired = (event: Event) => {
      const next = ((event as CustomEvent).detail?.kind as AuthNoticeKind) ?? 'expired';
      // 已经确认是"完全过期"就不要再被降级成只读提示, 反过来可以升级。
      setKind(prev => (prev === 'expired' ? prev : next));
    };
    window.addEventListener(AUTH_REQUIRED_EVENT, onAuthRequired);
    return () => window.removeEventListener(AUTH_REQUIRED_EVENT, onAuthRequired);
  }, []);

  if (!kind) return null;

  const action = ACTION_LABEL[kind];

  return (
    <div className='auth-expired-banner' role='alert'>
      <AlertTriangle size={15} />
      <span>{MESSAGES[kind]}</span>
      {action ? (
        <a className='auth-expired-action' href={loginUrl()}>
          {action}
        </a>
      ) : null}
    </div>
  );
}
