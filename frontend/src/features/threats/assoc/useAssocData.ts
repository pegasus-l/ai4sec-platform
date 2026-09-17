/**
 * 资产↔仓关联的共享数据入口 —— 关联视图(D/C)与仓库抽屉的「关联资产」区块读同一份缓存。
 *
 * 为什么单独一个模块:shared.ts 是纯函数,这里放 react-query 层。
 * query key / queryFn / staleTime 与 AssocView 完全一致,所以两处口径不会漂移,也不会重复拉取;
 * 抽屉从「今日关注 / 代码仓」进来时(关联视图没挂载过)才会真正发一次请求。
 */
import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  fetchAssociations, fetchAssets,
  type AssocAssetMeta, type AssocBundle, type AssocLink,
} from '../../../api/client';
import type { ThreatAsset } from '../../../types/threat';
import { assetFromItem } from '../threatAdapters';
import { repoLinksOf, sourceKey } from './shared';

/**
 * 关联 bundle。
 * `refetchInterval` 只在视图侧传(AssocView 传 60s):react-query 取所有 observer 里的**最小值**,
 * 抽屉不传 → 既不会自己开轮询,也不会把视图的 60s 顶掉;抽屉独占时则完全不轮询。
 */
export function useAssocBundle(refetchInterval?: number) {
  return useQuery({
    queryKey: ['threats-associations'],
    queryFn: fetchAssociations,
    staleTime: 60_000,
    refetchInterval,
  });
}

/** asset id(string) → 完整 ThreatAsset 查表(与关联视图 openAssetId 用的是同一份)。 */
export function useAssetLookup(): Map<string, ThreatAsset> {
  const { data } = useQuery({
    queryKey: ['threats-assets-lookup'],
    queryFn: fetchAssets,
    staleTime: 300_000,
  });
  return useMemo(() => {
    const m = new Map<string, ThreatAsset>();
    for (const item of data?.items ?? []) {
      const a = assetFromItem(item);
      m.set(a.id, a);
    }
    return m;
  }, [data]);
}

/** AssocAssetMeta → 完整 ThreatAsset;查表未命中时构造等价 thin 对象(字段与关联视图原兜底一致)。 */
export function resolveAsset(meta: AssocAssetMeta, map: Map<string, ThreatAsset>): ThreatAsset {
  const full = map.get(String(meta.id));
  if (full) return full;
  return {
    id: String(meta.id), title: meta.title, source: meta.source || meta.cat,
    sourceType: '', category: meta.cat, url: '', summary: '', score: 0,
    status: 'active', tags: [], raw: {},
    type: sourceKey(meta.source), confidence: 'unknown', evidence: '',
  };
}

/** 某个仓的全部关联边(按置信度排序;不吃关联视图的过滤器)。 */
export function useRepoLinks(repoId: string): {
  links: AssocLink[];
  meta: AssocBundle['meta'] | undefined;
  isLoading: boolean;
  isError: boolean;
} {
  const { data, isLoading, isError } = useAssocBundle();
  const links = useMemo(() => repoLinksOf(data, repoId), [data, repoId]);
  return { links, meta: data?.meta, isLoading, isError };
}
