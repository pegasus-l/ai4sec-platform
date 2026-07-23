import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { BookOpen, CalendarDays, Check, ExternalLink, Filter, Heart, Inbox, Layers3, ListFilter, MessageSquare, Network, Newspaper, Search, Sparkles, Star } from 'lucide-react';
import { Card, Drawer, EmptyState, MetricCard, Badge } from '../../components/ui';
import { fetchNews, postNewsAction, type NewsFilters } from './newsQueries';
import type { NewsItem, NewsView, Report, TodayResponse, TopicSummary } from './newsTypes';

const views: Array<{ id: NewsView; title: string; icon: typeof Newspaper }> = [
  { id: 'today', title: '今日精选', icon: Sparkles },
  { id: 'all', title: '全部动态', icon: Newspaper },
  { id: 'reports', title: '日报', icon: CalendarDays },
  { id: 'topics', title: '专题时间线', icon: Network }
];

const initialFilters: NewsFilters = { query: '', item_type: '', source: '', topic: '', status: '', sort: 'score', page: 1 };

export function NewsPage() {
  const [view, setView] = useUrlState<NewsView>('view', 'today');
  const [filters, setFilters] = useState<NewsFilters>(initialFilters);
  const [selected, setSelected] = useState<NewsItem | null>(null);
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: ['news', view, filters], queryFn: () => fetchNews(view, filters) });
  const action = useMutation({ mutationFn: ({ id, name }: { id: number; name: string }) => postNewsAction(id, name), onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['news'] }); if (selected) setSelected(null); } });
  const data = query.data as TodayResponse | { items: NewsItem[]; total?: number; page?: number; page_size?: number } | { items: Report[] } | { items: TopicSummary[] } | undefined;
  const allData = view === 'all' ? data as { items: NewsItem[]; total?: number; page?: number; page_size?: number } : undefined;

  useEffect(() => {
    const onPopState = () => setView((new URLSearchParams(window.location.search).get('view') as NewsView) || 'today');
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, [setView]);

  return <div className="news-workspace">
    <aside className="news-sidebar">
      <div className="news-kicker">NEWS INTELLIGENCE</div>
      <h1>资讯洞察</h1>
      <p className="news-intro">从多源发现、筛选和阅读 AI 安全资讯。</p>
      <nav className="news-nav">{views.map(({ id, title, icon: Icon }) => <button key={id} className={view === id ? 'active' : ''} onClick={() => setView(id)}><Icon size={16} />{title}<span>{id === 'all' && allData?.total !== undefined ? allData.total : ''}</span></button>)}</nav>
      <div className="news-flow"><span>工作流</span><p>发现 → 精选 → 阅读 → 反馈 → 能力转化</p></div>
    </aside>
    <main className="news-main">
      <div className="news-header"><div><span className="label">AI4SEC / NEWS</span><h2>{viewTitle(view)}</h2><p>{viewDescription(view)}</p></div><div className="news-header-actions"><Badge tone="green">SHADOW PIPELINE</Badge><button className="icon-button" title="刷新" onClick={() => query.refetch()}><Inbox size={17} /></button></div></div>
      {query.isError && <Card className="news-error">资讯接口暂时不可用，请检查后端服务和最近采集任务。</Card>}
      {query.isLoading ? <div className="news-loading"><div /><div /><div /></div> : <>
        {view === 'today' && <TodayView data={data as TodayResponse | undefined} onSelect={setSelected} />}
        {view === 'all' && <AllView data={allData} filters={filters} setFilters={setFilters} onSelect={setSelected} onAction={(id, name) => action.mutate({ id, name })} />}
        {view === 'reports' && <ReportsView data={data as { items: Report[] } | undefined} />}
        {view === 'topics' && <TopicsView data={data as { items: TopicSummary[] } | undefined} onSelectTopic={(topic) => { setFilters({ ...filters, topic, page: 1 }); setView('all'); }} />}
      </>}
    </main>
    <NewsDetail item={selected} close={() => setSelected(null)} onAction={(id, name) => action.mutate({ id, name })} />
  </div>;
}

function TodayView({ data, onSelect }: { data?: TodayResponse; onSelect: (item: NewsItem) => void }) {
  if (!data) return <EmptyState title="暂无今日资讯" description="运行资讯采集任务后，这里会显示今日精选。" />;
  return <div className="news-content"><div className="news-kpis">{[['新增资讯', data.kpis.new_count, 'sky'], ['今日精选', data.kpis.highlight_count, 'violet'], ['论文', data.kpis.paper_count, 'green'], ['项目', data.kpis.project_count, 'amber']].map(([label, value, tone]) => <MetricCard key={String(label)} label={String(label)} value={String(value)} tone={tone as 'sky' | 'violet' | 'green' | 'amber'} />)}</div><div className="section-heading"><div><span className="label">{data.date}</span><h3>今天值得先看</h3></div><span>{data.highlights.length} 条精选</span></div><div className="news-grid">{data.highlights.map(item => <NewsCard key={item.id} item={item} onSelect={onSelect} />)}</div><div className="news-columns"><Card><div className="panel-title"><h3>主题分布</h3><span>TOPICS</span></div>{data.topic_summary.map(topic => <div className="topic-row" key={topic.topic}><span>{topic.topic}</span><b>{topic.item_count}</b><i style={{ width: `${Math.min(100, topic.item_count * 12)}%` }} /></div>)}</Card><Card><div className="panel-title"><h3>来源概览</h3><span>SOURCES</span></div>{data.source_summary.map(source => <div className="source-row" key={source.id}><span><i className={`health-dot ${source.status}`} />{source.name}</span><b>{source.count}</b></div>)}</Card></div></div>;
}

function AllView({ data, filters, setFilters, onSelect, onAction }: { data?: { items: NewsItem[]; total?: number; page?: number; page_size?: number }; filters: NewsFilters; setFilters: (filters: NewsFilters) => void; onSelect: (item: NewsItem) => void; onAction: (id: number, name: string) => void }) {
  const update = (key: keyof NewsFilters, value: string) => setFilters({ ...filters, [key]: value, page: key === 'page' ? Number(value) : 1 });
  return <div className="news-content"><Card className="news-filter-card"><div className="filter-search"><Search size={17} /><input value={filters.query} onChange={event => update('query', event.target.value)} placeholder="搜索标题、摘要、来源或技术主题" /></div><div className="filter-row"><select value={filters.item_type} onChange={event => update('item_type', event.target.value)}><option value="">全部类型</option><option value="paper">论文</option><option value="project">项目</option><option value="article">文章</option><option value="tool">工具</option></select><select value={filters.source} onChange={event => update('source', event.target.value)}><option value="">全部来源</option><option value="arxiv">arXiv</option><option value="github">GitHub</option><option value="rss">RSS</option><option value="asis">ASIS</option></select><select value={filters.status} onChange={event => update('status', event.target.value)}><option value="">全部状态</option><option value="unread">未读</option><option value="read">已读</option><option value="bookmarked">已收藏</option><option value="later">稍后阅读</option><option value="ignored">已忽略</option></select><select value={filters.sort} onChange={event => update('sort', event.target.value)}><option value="score">综合推荐</option><option value="published_at">最新发布</option><option value="updated_at">最近更新</option></select><button className="filter-clear" onClick={() => setFilters(initialFilters)}><Filter size={14} />重置</button></div></Card><div className="list-meta"><span><ListFilter size={15} />共 {data?.total || 0} 条动态</span><span>论文、项目和文章统一展示</span></div><div className="news-list">{data?.items?.length ? data.items.map(item => <NewsListRow key={item.id} item={item} onSelect={onSelect} onAction={onAction} />) : <EmptyState title="没有匹配的资讯" description="可以调整关键词、类型或状态筛选。" />}</div><div className="pagination"><button disabled={(data?.page || 1) <= 1} onClick={() => update('page', String((data?.page || 1) - 1))}>上一页</button><span>第 {data?.page || 1} 页</span><button disabled={(data?.page || 1) * (data?.page_size || 24) >= (data?.total || 0)} onClick={() => update('page', String((data?.page || 1) + 1))}>下一页</button></div></div>;
}

function ReportsView({ data }: { data?: { items: Report[] } }) { return <div className="news-content"><div className="report-list">{data?.items?.length ? data.items.map(report => <Card key={report.report_date}><div className="report-date">{report.report_date}</div><h3>{report.title}</h3><p>{report.summary}</p><div className="report-meta"><Badge tone="violet">精选 {report.highlights.length}</Badge><Badge tone="sky">主题 {report.topic_sections.length}</Badge><span>{report.metrics.item_count || 0} 条采集</span></div><div className="report-topics">{report.topic_sections.slice(0, 5).map(section => <span key={section.topic}>{section.topic}</span>)}</div></Card>) : <EmptyState title="暂无日报" description="完成一次资讯采集和日报构建后，这里会显示日报。" />}</div></div>; }

function TopicsView({ data, onSelectTopic }: { data?: { items: TopicSummary[] }; onSelectTopic: (topic: string) => void }) { return <div className="news-content"><div className="timeline">{data?.items?.length ? data.items.map(topic => <button className="timeline-row" key={topic.topic} onClick={() => onSelectTopic(topic.topic)}><span className="timeline-dot" /><div><strong>{topic.topic}</strong><p>{topic.item_count} 条相关资讯 · 最近更新 {formatDate(topic.latest_at)}</p></div><span className="timeline-count">{topic.item_count}</span></button>) : <EmptyState title="暂无专题" description="资讯被分类和标注后会自动形成专题时间线。" />}</div></div>; }

function NewsCard({ item, onSelect }: { item: NewsItem; onSelect: (item: NewsItem) => void }) { return <button className="news-card" onClick={() => onSelect(item)}><div className="news-card-top"><Badge tone={item.item_type === 'paper' ? 'green' : item.item_type === 'project' ? 'violet' : 'sky'}>{typeLabel(item.item_type)}</Badge><span>{item.source}</span></div><h3>{item.title}</h3><p>{item.highlight || item.summary}</p><div className="news-card-bottom"><span>{formatDate(item.primary_date)}</span><strong>{Math.round(item.score || 0)}</strong></div></button>; }

function NewsListRow({ item, onSelect, onAction }: { item: NewsItem; onSelect: (item: NewsItem) => void; onAction: (id: number, name: string) => void }) { return <article className={`news-list-row ${item.user_state?.reading_state === 'read' ? 'read' : ''}`}><button className="row-main" onClick={() => onSelect(item)}><div className="news-card-top"><Badge tone={item.item_type === 'paper' ? 'green' : item.item_type === 'project' ? 'violet' : 'sky'}>{typeLabel(item.item_type)}</Badge><span>{item.source} · {formatDate(item.primary_date)}</span></div><h3>{item.title}</h3><p>{item.highlight || item.summary}</p><div className="tag-line">{item.technical_points.slice(0, 4).map(tag => <span key={tag}>{tag}</span>)}</div></button><div className="row-side"><strong>{Math.round(item.score || 0)}</strong><div><button title="收藏" onClick={() => onAction(item.id, 'bookmark')}><Heart size={15} fill={item.user_state?.reading_state === 'bookmarked' ? 'currentColor' : 'none'} /></button><button title="已读" onClick={() => onAction(item.id, 'read')}><Check size={15} /></button></div></div></article>; }

function NewsDetail({ item, close, onAction }: { item: NewsItem | null; close: () => void; onAction: (id: number, name: string) => void }) { return <Drawer open={Boolean(item)} title={item?.title || ''} subtitle={item ? `${typeLabel(item.item_type)} · ${item.source}` : ''} onClose={close}>{item && <div className="news-detail"><div className="detail-actions"><button onClick={() => onAction(item.id, 'bookmark')}><Heart size={15} />收藏</button><button onClick={() => onAction(item.id, 'later')}><BookOpen size={15} />稍后阅读</button><button onClick={() => onAction(item.id, 'read')}><Check size={15} />已读</button>{item.source_url && <a href={item.source_url} target="_blank" rel="noreferrer"><ExternalLink size={15} />来源</a>}</div><div className="detail-score"><span>推荐评分</span><strong>{Math.round(item.score || 0)}</strong><p>{scoreReasons(item)}</p></div><Card><h3>摘要</h3><p>{item.summary || '暂无摘要。'}</p>{item.highlight && <p className="detail-highlight">{item.highlight}</p>}</Card>{item.paper && <Card><h3>论文信息</h3><dl><dt>arXiv ID</dt><dd>{item.paper.arxiv_id || '—'}</dd><dt>作者</dt><dd>{item.paper.authors.join(', ') || '—'}</dd><dt>代码地址</dt><dd>{item.paper.code_url || '—'}</dd></dl></Card>}{item.project && <Card><h3>项目指标</h3><div className="project-metrics"><span><Star size={14} />{item.project.stars}</span><span><Layers3 size={14} />{item.project.forks}</span><span>{item.project.language || '未知语言'}</span></div><dl><dt>仓库</dt><dd>{item.project.repo_full_name || '—'}</dd><dt>更新时间</dt><dd>{formatDate(item.project.updated_at)}</dd></dl></Card>}<Card><h3>技术点</h3><div className="detail-tags">{item.technical_points.length ? item.technical_points.map(point => <Badge key={point} tone="sky">{point}</Badge>) : <span>暂无技术点</span>}</div></Card><button className="promote-button" onClick={() => onAction(item.id, 'promote-to-capability')}><MessageSquare size={15} />流转到能力洞察</button></div>}</Drawer>; }

function useUrlState<T extends string>(key: string, fallback: T): [T, (value: T) => void] { const initial = (new URLSearchParams(window.location.search).get(key) as T) || fallback; const [value, setValue] = useState<T>(initial); const update = (next: T) => { setValue(next); const url = new URL(window.location.href); url.searchParams.set(key, next); window.history.pushState({}, '', url); }; return [value, update]; }
function viewTitle(view: NewsView): string { return ({ today: '今日精选', all: '全部动态', reports: '日报', topics: '专题时间线' })[view]; }
function viewDescription(view: NewsView): string { return ({ today: '先看今天最值得阅读的论文、项目和安全资讯。', all: '用统一列表检索、筛选和处理所有资讯。', reports: '按日期回顾采集结果、重点内容和主题变化。', topics: '围绕安全主题查看论文、项目和文章的时间线。' })[view]; }
function typeLabel(type: string): string { return ({ paper: '论文', project: '项目', article: '文章', tool: '工具', report: '报告' } as Record<string, string>)[type] || type; }
function formatDate(value: string): string { return value ? value.slice(0, 10) : '未知日期'; }
function scoreReasons(item: NewsItem): string { const scoring = item.payload.scoring; if (!scoring || typeof scoring !== 'object') return '基于相关性、安全价值、新鲜度和信息完整度综合评分。'; const reasons = (scoring as { reasons?: unknown }).reasons; return Array.isArray(reasons) ? reasons.map(String).join('；') : '基于相关性、安全价值、新鲜度和信息完整度综合评分。'; }
