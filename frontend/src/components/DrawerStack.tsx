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
 *   // 正文里改头部(例:代码仓抽屉详情拉回来后把副标题换成真实链接):
 *   render: (drawerId) => <Content onLoaded={(url) => update(drawerId, { subtitle: url })} />
 *   // Close all (mask click):
 *   clear();
 *
 * Visual: each drawer offset by 24px to the left, z-index increases with depth.
 * Close button on drawer N closes N and all above.
 */

export interface DrawerEntry {
  id: string;
  title: string;
  /** 头部第二行。多数抽屉传字符串;代码仓抽屉传的是可点链接(整页只出现一次仓库 URL)。 */
  subtitle?: ReactNode;
  /** 抽屉正文。入参是当前抽屉 id,正文可用它把加载完成后的真实数据回写到头部(见 update)。 */
  render: (drawerId: string) => ReactNode;
}

interface DrawerStackContextValue {
  stack: DrawerEntry[];
  push: (entry: Omit<DrawerEntry, 'id'>) => void;
  /** 就地改头部标题/副标题。目前只有代码仓抽屉用:详情到位后把占位文案换成真实仓库链接。 */
  update: (id: string, patch: Partial<Pick<DrawerEntry, 'title' | 'subtitle'>>) => void;
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

  const update = useCallback(
    (id: string, patch: Partial<Pick<DrawerEntry, 'title' | 'subtitle'>>) => {
      // 抽屉已被关掉时 map 找不到 id,自然是个 no-op —— 正文里的 useEffect 收尾不必再判存活。
      setStack((prev) => prev.map((entry) => (entry.id === id ? { ...entry, ...patch } : entry)));
    },
    [],
  );

  const pop = useCallback(() => {
    setStack((prev) => prev.slice(0, -1));
  }, []);

  const clear = useCallback(() => setStack([]), []);

  const closeAt = useCallback((index: number) => {
    setStack((prev) => prev.slice(0, index));
  }, []);

  return (
    <DrawerStackContext.Provider value={{ stack, push, update, pop, clear }}>
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
            <div className="drawer-body">{entry.render(entry.id)}</div>
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
