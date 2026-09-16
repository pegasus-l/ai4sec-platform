import { useEffect, useState } from 'react';
import { AlertTriangle } from 'lucide-react';
import { AUTH_REQUIRED_EVENT, loginUrl } from '../api/client';

/**
 * 登录已过期横幅。
 *
 * 为什么需要它: 能力洞察挂在入口网关(136 radar)的 `/insights` 前缀下, 而 `/insights/*`
 * 在那台 nginx 里是**直转隧道**的 —— 绕过了 radar 自己的会话校验。于是 cookie 过期后:
 * 页面(SPA)照旧返回 200、只有每个 `/api/*` 返回 401, 用户看到的是"空页面 + 没有任何提示
 * + 不跳登录页"。后端现在会对"浏览器导航"补 307 跳转(见 middleware.py); 这个组件负责
 * 处理**不打导航**的那些请求 —— SPA 内部切域、复现状态每 5s 的轮询 —— 在页面原地给出口。
 *
 * 不做自动跳转: 过期时用户可能正在看复现日志, 直接把人踢走会丢掉现场; 由用户点"重新登录"
 * 决定, 回跳地址就是当前这一页(client.ts 的 loginUrl)。
 */
export function AuthExpiredBanner() {
  const [expired, setExpired] = useState(false);

  useEffect(() => {
    const onAuthRequired = () => setExpired(true);
    window.addEventListener(AUTH_REQUIRED_EVENT, onAuthRequired);
    return () => window.removeEventListener(AUTH_REQUIRED_EVENT, onAuthRequired);
  }, []);

  if (!expired) return null;

  return (
    <div className='auth-expired-banner' role='alert'>
      <AlertTriangle size={15} />
      <span>登录已过期，页面数据已停止更新。</span>
      <a className='auth-expired-action' href={loginUrl()}>
        重新登录
      </a>
    </div>
  );
}
