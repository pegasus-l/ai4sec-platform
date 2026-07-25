import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { PropsWithChildren } from 'react';
import { DrawerStackProvider } from '../components/DrawerStack';
import { ToastProvider } from '../components/Toast';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 30_000, refetchOnWindowFocus: false }
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
