import { useEffect, useRef, useState } from 'react';
import { AlertTriangle } from 'lucide-react';
import { AUTH_REQUIRED_EVENT, loginUrl, type AuthNoticeDetail, type AuthNoticeKind } from '../api/client';

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
 * 同日再改: 用户点了按钮却被 403 挡住, 再让他自己点一次「重新登录」是多余的一步。
 * 现在**用户主动写操作触发的失效会自动跳登录页**(倒计时见 AUTO_REDIRECT_SECONDS)。
 * 仍然不自动跳的三种情况, 每一条都有具体原因:
 *   1. **后台轮询触发的**(autoRedirect=false): 用户可能正开着复现日志页看输出, 把人踢走
 *      会丢掉现场 —— 只在原地提示。
 *   2. **账号本身只读**(readonly_account): 登录也解决不了, 跳过去只是白白多一步。
 *   3. **页面被嵌在跨源 iframe 里**(平台会被嵌进第三方系统, 见 nginx 的 /insights 转发):
 *      跳转只会把宿主的页面换成本平台的登录页, 而且第三方 iframe 里 SameSite=Lax 的登录
 *      cookie 根本回不来 —— 越跳越糟。这种情况改成"在新窗口登录", 登录后刷新原页面即可。
 */
const AUTO_REDIRECT_SECONDS = 3;

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

/** 跨源 iframe 里也可安全求值(比较身份不会抛, 但个别沙箱会, 兜住)。 */
function isTopLevelWindow(): boolean {
  try {
    return window.top === window.self;
  } catch {
    return false;
  }
}

export function AuthExpiredBanner() {
  const [kind, setKind] = useState<AuthNoticeKind | null>(null);
  const [countdown, setCountdown] = useState<number | null>(null);
  // 用户点过「留在此页」就不要再自动跳 —— 用 ref 因为监听器只在挂载时注册一次。
  const dismissed = useRef(false);
  const topLevel = useRef(isTopLevelWindow());

  useEffect(() => {
    const onAuthRequired = (event: Event) => {
      const detail = (event as CustomEvent<AuthNoticeDetail>).detail;
      const next = detail?.kind ?? 'expired';
      // 已经确认是"完全过期"就不要再被降级成只读提示, 反过来可以升级。
      setKind(prev => (prev === 'expired' ? prev : next));
      if (!detail?.autoRedirect) return;
      if (next === 'readonly_account') return;
      if (!topLevel.current || dismissed.current) return;
      setCountdown(AUTO_REDIRECT_SECONDS);
    };
    window.addEventListener(AUTH_REQUIRED_EVENT, onAuthRequired);
    return () => window.removeEventListener(AUTH_REQUIRED_EVENT, onAuthRequired);
  }, []);

  useEffect(() => {
    if (countdown === null) return;
    if (countdown <= 0) {
      // assign 而不是 replace: 登录页留在历史里, 用户按返回还能回到刚才那一页。
      window.location.assign(loginUrl());
      return;
    }
    const timer = window.setTimeout(() => setCountdown(c => (c === null ? null : c - 1)), 1000);
    return () => window.clearTimeout(timer);
  }, [countdown]);

  if (!kind) return null;

  const action = ACTION_LABEL[kind];
  const redirecting = countdown !== null;

  return (
    <div className='auth-expired-banner' role='alert'>
      <AlertTriangle size={15} />
      <span>
        {MESSAGES[kind]}
        {redirecting ? ` ${countdown} 秒后自动前往登录页。` : null}
        {!topLevel.current && action ? ' 请在新窗口登录后刷新本页。' : null}
      </span>
      {action ? (
        <a
          className='auth-expired-action'
          href={loginUrl()}
          target={topLevel.current ? undefined : '_blank'}
          rel='noreferrer'
        >
          {redirecting ? '立即登录' : action}
        </a>
      ) : null}
      {redirecting ? (
        <button
          type='button'
          className='auth-expired-dismiss'
          onClick={() => {
            dismissed.current = true;
            setCountdown(null);
          }}
        >
          留在此页
        </button>
      ) : null}
    </div>
  );
}
