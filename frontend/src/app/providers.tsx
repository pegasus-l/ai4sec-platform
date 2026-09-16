import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { PropsWithChildren } from 'react';
import { DrawerStackProvider } from '../components/DrawerStack';
import { ToastProvider } from '../components/Toast';

const queryClient = new QueryClient({
  defaultOptions: {
    // refetchIntervalInBackground: 页面不可见(标签页隐藏)时不轮询 —— 这就是「只在页面可见时刷新」。
    // react-query 5 默认值本来就是 false(focusManager 按 visibilitychange 判定), 这里显式写出,
    // 防止日后有人改全局默认时把隐藏标签页的轮询打开。
    queries: { staleTime: 30_000, refetchOnWindowFocus: false, refetchIntervalInBackground: false }
  }
});

export function Providers({ children }: PropsWithChildren) {
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <DrawerStackProvider>{children}</DrawerStackProvider>
      </ToastProvider>
    </QueryClientProvider>
  );
}
