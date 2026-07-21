import { createContext, useCallback, useContext, useState, type ReactNode } from 'react';

/**
 * DrawerStack — stack-based drawer system supporting nested drawers.
 *
 * Usage:
 *   const { push, pop, clear } = useDrawerStack();
 *   push({ title: '仓库详情', subtitle: 'org/name', render: () => <RepoContent repo={repo} /> });
 *   // From within repo drawer, push vuln drawer (does NOT close repo drawer):
 *   push({ title: '漏洞详情', subtitle: 'CVE-xxx', render: () => <VulnContent vuln={vuln} /> });
 *   // Close top drawer only:
 *   pop();
 *   // Close all (mask click):
 *   clear();
 *
 * Visual: each drawer offset by 24px to the left, z-index increases with depth.
 * Close button on drawer N closes N and all above.
 */

export interface DrawerEntry {
  id: string;
  title: string;
  subtitle?: string;
  render: () => ReactNode;
}

interface DrawerStackContextValue {
  stack: DrawerEntry[];
  push: (entry: Omit<DrawerEntry, 'id'>) => void;
  pop: () => void;
  clear: () => void;
}

const DrawerStackContext = createContext<DrawerStackContextValue | null>(null);

const OFFSET_PER_LEVEL = 24; // px
const BASE_Z_INDEX = 21; // matches existing .drawer z-index in global.css

export function DrawerStackProvider({ children }: { children: ReactNode }) {
  const [stack, setStack] = useState<DrawerEntry[]>([]);

  const push = useCallback((entry: Omit<DrawerEntry, 'id'>) => {
    setStack((prev) => [
      ...prev,
      { ...entry, id: `drawer-${Date.now()}-${prev.length}` },
    ]);
  }, []);

  const pop = useCallback(() => {
    setStack((prev) => prev.slice(0, -1));
  }, []);

  const clear = useCallback(() => setStack([]), []);

  const closeAt = useCallback((index: number) => {
    setStack((prev) => prev.slice(0, index));
  }, []);

  return (
    <DrawerStackContext.Provider value={{ stack, push, pop, clear }}>
      {children}
      {stack.length > 0 && (
        <div className="drawer-mask open" onClick={clear} />
      )}
      {stack.map((entry, index) => (
        <aside
          key={entry.id}
          className="drawer open"
          style={{
            right: `${index * OFFSET_PER_LEVEL}px`,
            zIndex: BASE_Z_INDEX + index,
          }}
        >
          <div className="drawer-panel">
            <div className="drawer-head">
              <div>
                <span className="label">DETAIL</span>
                <h2>{entry.title}</h2>
                {entry.subtitle && (
                  <p className="muted small" style={{ margin: '6px 0 0' }}>
                    {entry.subtitle}
                  </p>
                )}
              </div>
              <button
                className="close"
                onClick={() => closeAt(index)}
                aria-label="关闭抽屉"
              >
                ×
              </button>
            </div>
            <div className="drawer-body">{entry.render()}</div>
          </div>
        </aside>
      ))}
    </DrawerStackContext.Provider>
  );
}

export function useDrawerStack(): DrawerStackContextValue {
  const ctx = useContext(DrawerStackContext);
  if (!ctx) {
    throw new Error('useDrawerStack must be used within DrawerStackProvider');
  }
  return ctx;
}
