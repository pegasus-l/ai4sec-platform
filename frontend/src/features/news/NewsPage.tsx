import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { BookOpen, CalendarDays, Check, ExternalLink, Filter, Heart, Inbox, Layers3, MessageSquare, Network, Newspaper, Search, Sparkles, Star, X } from 'lucide-react';
import { Badge, Card, Drawer, EmptyState, MetricCard } from '../../components/ui';
import { fetchNews, fetchReport, fetchTechMap, postNewsAction, type NewsFilters } from './newsQueries';
import type { NewsItem, NewsView, Report, TechMapItem, TodayResponse, TopicSummary } from './newsTypes';

const views: Array<{ id: NewsView; title: string; icon: typeof Newspaper }> = [
  { id: 'today', title: '今日精选', icon: Sparkles },
  { id: 'all', title: '全部动态', icon: Newspaper },
  { id: 'reports', title: '日报', icon: CalendarDays },
  { id: 'topics', title: '专题时间线', icon: Network }
];

function initialFilters(): NewsFilters {
  const params = new URLSearchParams(window.location.search);
  return { query: '', item_type: '', source: '', topic: params.get('topic') || '', tech_dimensions: params.getAll('tech_dimension'), tech_categories: params.getAll('tech_category'), tech_points: params.getAll('tech_point'), tech_match: params.get('tech_match') === 'all' ? 'all' : 'any', status: '', sort: 'score', page: 1 };
}

export function NewsPage() {
  const [view, setView] = useUrlState<NewsView>('view', 'today');
  const [filters, setFilters] = useState<NewsFilters>(initialFilters);
  const [selected, setSelected] = useState<NewsItem | null>(null);
  const [selectedReportDate, setSelectedReportDate] = useState('');
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: ['news', view, filters], queryFn: () => fetchNews(view, filters) });
  const reportQuery = useQuery({ queryKey: ['news-report', selectedReportDate], queryFn: () => fetchReport(selectedReportDate), enabled: Boolean(selectedReportDate) });
  const action = useMutation({
    mutationFn: ({ id, name }: { id: number; name: string }) => postNewsAction(id, name),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['news'] }); setSelected(null); }
  });
  const data = query.data as TodayResponse | { items: NewsItem[]; total?: number; page?: number; page_size?: number } | { items: Report[] } | { items: TopicSummary[] } | undefined;
  const allData = view === 'all' ? data as { items: NewsItem[]; total?: number; page?: number; page_size?: number } : undefined;

  useEffect(() => {
    const url = new URL(window.location.href);
    if (filters.topic) url.searchParams.set('topic', filters.topic);
    else url.searchParams.delete('topic');
    ['tech_dimension', 'tech_category', 'tech_point', 'tech_match'].forEach(key => url.searchParams.delete(key));
    filters.tech_dimensions.forEach(value => url.searchParams.append('tech_dimension', value));
    filters.tech_categories.forEach(value => url.searchParams.append('tech_category', value));
    filters.tech_points.forEach(value => url.searchParams.append('tech_point', value));
    if (filters.tech_dimensions.length + filters.tech_categories.length + filters.tech_points.length > 1) url.searchParams.set('tech_match', filters.tech_match);
    window.history.replaceState({}, '', url);
  }, [filters.topic, filters.tech_dimensions, filters.tech_categories, filters.tech_points, filters.tech_match]);

  const openTopic = (topic: string) => {
    setFilters(current => ({ ...current, topic, page: 1 }));
    setView('all');
  };

  return <div className="news-workspace">
    <aside className="news-sidebar">
      <div className="news-kicker">NEWS INTELLIGENCE</div>
      <h1>资讯洞察</h1>
      <p className="news-intro">持续发现 AI 安全论文与开源项目，形成可跟踪、可阅读、可反馈的资讯流。</p>
      <nav className="news-nav">{views.map(({ id, title, icon: Icon }) => <button key={id} className={view === id ? 'active' : ''} onClick={() => setView(id)}><Icon size={16} />{title}<span>{id === 'all' && allData?.total !== undefined ? allData.total : ''}</span></button>)}</nav>
      <div className="news-flow"><span>工作流</span><p>发现 → 精选 → 阅读 → 反馈 → 专题沉淀</p></div>
    </aside>
    <main className="news-main">
      <div className="news-header"><div><span className="label">AI4SEC / NEWS</span><h2>{viewTitle(view)}</h2><p>{viewDescription(view)}</p></div><div className="news-header-actions"><Badge tone="green">论文 + 项目</Badge><button className="icon-button" title="刷新" onClick={() => query.refetch()}><Inbox size={17} /></button></div></div>
      {query.isError && <Card className="news-error">资讯接口暂时不可用，请检查后端服务和最近采集任务。</Card>}
      {query.isLoading ? <div className="news-loading"><div /><div /><div /></div> : <>
        {view === 'today' && <TodayView data={data as TodayResponse | undefined} onSelect={setSelected} />}
        {view === 'all' && <AllView data={allData} filters={filters} setFilters={setFilters} onSelect={setSelected} onAction={(id, name) => action.mutate({ id, name })} />}
        {view === 'reports' && <ReportsView data={data as { items: Report[] } | undefined} onOpen={setSelectedReportDate} />}
        {view === 'topics' && <TopicsView data={data as { items: TopicSummary[] } | undefined} onSelectTopic={openTopic} />}
      </>}
    </main>
    <NewsDetail item={selected} close={() => setSelected(null)} onAction={(id, name) => action.mutate({ id, name })} />
    <ReportDetail report={reportQuery.data} loading={reportQuery.isLoading} close={() => setSelectedReportDate('')} onSelect={item => { setSelectedReportDate(''); setSelected(item); }} />
  </div>;
}

function TodayView({ data, onSelect }: { data?: TodayResponse; onSelect: (item: NewsItem) => void }) {
  if (!data) return <EmptyState title="暂无今日资讯" description="运行资讯采集任务后，这里会显示今日精选。" />;
  return <div className="news-content">
    <div className="news-kpis">{[['新增资讯', data.kpis.new_count, 'sky'], ['今日精选', data.kpis.highlight_count, 'violet'], ['论文', data.kpis.paper_count, 'green'], ['项目', data.kpis.project_count, 'amber']].map(([label, value, tone]) => <MetricCard key={String(label)} label={String(label)} value={String(value)} tone={tone as 'sky' | 'violet' | 'green' | 'amber'} />)}</div>
    <div className="section-heading"><div><span className="label">{data.date}</span><h3>今天值得先看</h3></div><span>{data.highlights.length} 条精选</span></div>
    <div className="news-grid">{data.highlights.map(item => <NewsCard key={item.id} item={item} onSelect={onSelect} />)}</div>
    <div className="news-columns"><Card><div className="panel-title"><h3>中文主题分布</h3><span>TOPICS</span></div>{data.topic_summary.map(topic => <div className="topic-row" key={topic.topic}><span>{topic.topic}</span><b>{topic.item_count}</b><i style={{ width: `${Math.min(100, topic.item_count * 12)}%` }} /></div>)}</Card><Card><div className="panel-title"><h3>来源概览</h3><span>SOURCES</span></div>{data.source_summary.map(source => <div className="source-row" key={source.id}><span><i className={`health-dot ${source.status}`} />{source.name}</span><b>{source.count}</b></div>)}</Card></div>
  </div>;
}

function AllView({ data, filters, setFilters, onSelect, onAction }: { data?: { items: NewsItem[]; total?: number; page?: number; page_size?: number }; filters: NewsFilters; setFilters: (filters: NewsFilters) => void; onSelect: (item: NewsItem) => void; onAction: (id: number, name: string) => void }) {
  const [techOpen, setTechOpen] = useState(false);
  const techMapQuery = useQuery({ queryKey: ['news-tech-map'], queryFn: fetchTechMap });
  const update = (key: keyof NewsFilters, value: string | number) => setFilters({ ...filters, [key]: key === 'page' ? Number(value) : value, page: key === 'page' ? Number(value) : 1 } as NewsFilters);
  const updateTech = (key: 'tech_dimensions' | 'tech_categories' | 'tech_points', values: string[]) => setFilters({ ...filters, [key]: values, page: 1 });
  const selectedTechCount = filters.tech_dimensions.length + filters.tech_categories.length + filters.tech_points.length;
  const togglePoint = (point: string) => updateTech('tech_points', toggleValue(filters.tech_points, point));
  const hotPoints = [...(techMapQuery.data?.items || [])].filter(item => item.count > 0).sort((left, right) => right.count - left.count).slice(0, 6);
  const clearFilters = () => setFilters({ ...initialFilters(), topic: '', tech_dimensions: [], tech_categories: [], tech_points: [], tech_match: 'any' });
  return <div className="news-content">
    {filters.topic && <div className="active-topic"><div><span>当前专题</span><strong>{filters.topic}</strong></div><button onClick={() => update('topic', '')}>清除专题筛选</button></div>}
    <Card className="news-filter-card"><div className="filter-search"><Search size={17} /><input value={filters.query} onChange={event => update('query', event.target.value)} placeholder="搜索论文、项目、摘要或技术主题" /></div><div className="filter-row"><select value={filters.item_type} onChange={event => update('item_type', event.target.value)}><option value="">全部类型</option><option value="paper">论文</option><option value="project">项目</option></select><select value={filters.source} onChange={event => update('source', event.target.value)}><option value="">全部来源</option><option value="arxiv">arXiv</option><option value="github">GitHub</option></select><select value={filters.status} onChange={event => update('status', event.target.value)}><option value="">全部状态</option><option value="unread">未读</option><option value="read">已读</option><option value="bookmarked">已收藏</option><option value="later">稍后阅读</option><option value="ignored">已忽略</option></select><select value={filters.sort} onChange={event => update('sort', event.target.value)}><option value="score">按推荐分</option><option value="published_at">按发布时间</option><option value="updated_at">按更新时间</option></select><button className={`tech-filter-trigger ${selectedTechCount ? 'active' : ''}`} onClick={() => setTechOpen(true)}><Filter size={14} />技术分类{selectedTechCount ? ` · ${selectedTechCount}` : ''}</button>{Object.values(filters).some(value => Array.isArray(value) ? value.length : value && value !== 'score' && value !== 'any' && value !== 1) && <button className="filter-clear" onClick={clearFilters}>清除筛选</button>}</div>{hotPoints.length > 0 && <div className="quick-tech"><span>热门技术点</span>{hotPoints.map(item => <button className={filters.tech_points.includes(item.point) ? 'active' : ''} key={`${item.category}/${item.point}`} onClick={() => togglePoint(item.point)}>{item.point}<b>{item.count}</b></button>)}<button className="more-tech" onClick={() => setTechOpen(true)}>更多分类 →</button></div>}{selectedTechCount > 0 && <SelectedTechFilters filters={filters} updateTech={updateTech} />}</Card>
    <div className="list-meta"><span>共 {data?.total || 0} 条</span><span>{selectedTechCount ? `匹配${filters.tech_match === 'all' ? '全部' : '任一'}已选技术分类` : filters.topic ? `已按「${filters.topic}」筛选` : '仅展示论文与项目'}</span></div>
    {!data?.items.length ? <EmptyState title="没有匹配的资讯" description="请调整筛选条件或等待下一次采集。" /> : <div className="news-list">{data.items.map(item => <NewsListRow key={item.id} item={item} onSelect={onSelect} onAction={onAction} onTechPoint={togglePoint} />)}</div>}
    {data && (data.total || 0) > (data.page_size || 24) && <div className="pagination"><button disabled={(data.page || 1) <= 1} onClick={() => update('page', String((data.page || 1) - 1))}>上一页</button><span>第 {data.page || 1} 页</span><button disabled={(data.page || 1) * (data.page_size || 24) >= (data.total || 0)} onClick={() => update('page', String((data.page || 1) + 1))}>下一页</button></div>}
    <TechFilterDrawer open={techOpen} close={() => setTechOpen(false)} items={techMapQuery.data?.items || []} filters={filters} updateTech={updateTech} clearTech={() => setFilters({ ...filters, tech_dimensions: [], tech_categories: [], tech_points: [], tech_match: 'any', page: 1 })} setMatch={value => setFilters({ ...filters, tech_match: value, page: 1 })} resultCount={data?.total || 0} />
  </div>;
}

function SelectedTechFilters({ filters, updateTech }: { filters: NewsFilters; updateTech: (key: 'tech_dimensions' | 'tech_categories' | 'tech_points', values: string[]) => void }) {
  const groups: Array<{ key: 'tech_dimensions' | 'tech_categories' | 'tech_points'; label: string; values: string[] }> = [
    { key: 'tech_dimensions', label: '维度', values: filters.tech_dimensions },
    { key: 'tech_categories', label: '分类', values: filters.tech_categories },
    { key: 'tech_points', label: '技术点', values: filters.tech_points }
  ];
  return <div className="selected-tech-filters"><span>已选</span>{groups.flatMap(group => group.values.map(value => <button key={`${group.key}/${value}`} onClick={() => updateTech(group.key, group.values.filter(item => item !== value))}><small>{group.label}</small>{value}<X size={12} /></button>))}</div>;
}

function TechFilterDrawer({ open, close, items, filters, updateTech, clearTech, setMatch, resultCount }: { open: boolean; close: () => void; items: TechMapItem[]; filters: NewsFilters; updateTech: (key: 'tech_dimensions' | 'tech_categories' | 'tech_points', values: string[]) => void; clearTech: () => void; setMatch: (value: 'any' | 'all') => void; resultCount: number }) {
  const [search, setSearch] = useState('');
  const filtered = useMemo(() => {
    const keyword = search.trim().toLowerCase();
    return keyword ? items.filter(item => `${item.dimension} ${item.category} ${item.point}`.toLowerCase().includes(keyword)) : items;
  }, [items, search]);
  const dimensions = useMemo(() => {
    const grouped = new Map<string, Map<string, TechMapItem[]>>();
    filtered.forEach(item => {
      if (!grouped.has(item.dimension)) grouped.set(item.dimension, new Map());
      const categories = grouped.get(item.dimension)!;
      if (!categories.has(item.category)) categories.set(item.category, []);
      categories.get(item.category)!.push(item);
    });
    return grouped;
  }, [filtered]);
  const selectedCount = filters.tech_dimensions.length + filters.tech_categories.length + filters.tech_points.length;
  return <Drawer open={open} title="技术分类" subtitle={`AI Agent 技术地图 · ${items.length} 个技术点`} onClose={close}>
    <div className="tech-filter-panel">
      <div className="tech-filter-search"><Search size={16} /><input value={search} onChange={event => setSearch(event.target.value)} placeholder="搜索 MCP、记忆、规划……" />{search && <button onClick={() => setSearch('')}><X size={14} /></button>}</div>
      <div className="tech-match-mode"><div><strong>匹配方式</strong><span>选择多个分类时如何组合</span></div><div><button className={filters.tech_match === 'any' ? 'active' : ''} onClick={() => setMatch('any')}>任一</button><button className={filters.tech_match === 'all' ? 'active' : ''} onClick={() => setMatch('all')}>全部</button></div></div>
      <div className="tech-tree">
        {[...dimensions.entries()].map(([dimension, categories]) => {
          const dimensionItems = [...categories.values()].flat();
          const dimensionCount = dimensionItems.reduce((sum, item) => sum + item.count, 0);
          return <details key={dimension} open={Boolean(search) || filters.tech_dimensions.includes(dimension)}>
            <summary><label onClick={event => event.stopPropagation()}><input type="checkbox" checked={filters.tech_dimensions.includes(dimension)} onChange={() => updateTech('tech_dimensions', toggleValue(filters.tech_dimensions, dimension))} /><span>{dimension}</span></label><b>{dimensionCount}</b></summary>
            <div className="tech-categories">{[...categories.entries()].map(([category, points]) => <div className="tech-category" key={`${dimension}/${category}`}><label className="tech-category-head"><input type="checkbox" checked={filters.tech_categories.includes(category)} onChange={() => updateTech('tech_categories', toggleValue(filters.tech_categories, category))} /><span>{category}</span><b>{points.reduce((sum, item) => sum + item.count, 0)}</b></label><div className="tech-points">{points.map(item => <label className={item.count ? '' : 'empty'} key={`${item.category}/${item.point}`}><input type="checkbox" checked={filters.tech_points.includes(item.point)} onChange={() => updateTech('tech_points', toggleValue(filters.tech_points, item.point))} /><span>{item.point}</span><b>{item.count}</b></label>)}</div></div>)}</div>
          </details>;
        })}
        {!dimensions.size && <EmptyState title="没有匹配的技术分类" description="尝试使用更短的关键词。" />}
      </div>
      <div className="tech-filter-footer"><button className="reset" disabled={!selectedCount} onClick={clearTech}>重置</button><button className="confirm" onClick={close}>查看 {resultCount} 条结果</button></div>
    </div>
  </Drawer>;
}

function ReportsView({ data, onOpen }: { data?: { items: Report[] }; onOpen: (date: string) => void }) {
  if (!data?.items.length) return <EmptyState title="暂无日报" description="日报由每日资讯流水线生成，完成采集后即可按日期查看。" />;
  return <div className="report-list">{data.items.map(report => <button className="report-card" key={report.report_date} onClick={() => onOpen(report.report_date)}><span className="report-date">{report.report_date}</span><h3>{report.title}</h3><p>{report.summary}</p><div className="report-meta"><span>{report.metrics.item_count || 0} 条资讯</span><span>·</span><span>{report.metrics.highlight_count || 0} 条精选</span><span>点击查看日报详情 →</span></div><div className="report-topics">{report.topic_sections.slice(0, 6).map(section => <span key={section.topic}>{section.topic}</span>)}</div></button>)}</div>;
}

function ReportDetail({ report, loading, close, onSelect }: { report?: Report; loading: boolean; close: () => void; onSelect: (item: NewsItem) => void }) {
  return <Drawer open={loading || Boolean(report)} title={report?.title || '正在加载日报'} subtitle={report?.report_date} onClose={close}>{loading ? <div className="news-loading"><div /><div /></div> : report && <div className="news-detail"><Card><h3>日报摘要</h3><p>{report.summary}</p></Card><div className="report-detail-items">{(report.items || []).map(item => <button key={item.id} onClick={() => onSelect(item)}><Badge tone={item.item_type === 'paper' ? 'green' : 'violet'}>{typeLabel(item.item_type)}</Badge><div><strong>{displayTheme(item)}</strong><p>{promoLine(item)}</p></div></button>)}</div></div>}</Drawer>;
}

function TopicsView({ data, onSelectTopic }: { data?: { items: TopicSummary[] }; onSelectTopic: (topic: string) => void }) {
  if (!data?.items.length) return <EmptyState title="暂无专题" description="系统会按中文安全主题自动聚合，也可在后续配置持续跟踪专题。" />;
  return <div><Card className="topic-explainer"><strong>当前为自动聚合专题</strong><p>点击专题会进入全部动态并带上专题筛选。下一阶段可增加类似 ASIS 的“跟踪专题”，配置别名、关键词和数据源，持续收集某一事件的后续论文与项目。</p></Card><div className="timeline">{data.items.map(topic => <button className="timeline-row" key={topic.topic} onClick={() => onSelectTopic(topic.topic)}><span className="timeline-dot" /><div><strong>{topic.topic}</strong><p>最近更新 {formatDate(topic.latest_at)} · 点击查看筛选结果</p></div><span className="timeline-count">{topic.item_count}</span></button>)}</div></div>;
}

function NewsCard({ item, onSelect }: { item: NewsItem; onSelect: (item: NewsItem) => void }) {
  return <button className="news-card" onClick={() => onSelect(item)}><div className="news-card-top"><Badge tone={item.item_type === 'paper' ? 'green' : 'violet'}>{typeLabel(item.item_type)}</Badge><span>{displayTopic(item)}</span></div><h3>{displayTheme(item)}</h3>{displayTheme(item) !== item.title && <div className="original-title">{item.title}</div>}<div className="content-line"><b>宣传</b><span>{promoLine(item)}</span></div><div className="content-line highlight-line"><b>亮点</b><span>{highlightLine(item)}</span></div><div className="tag-line">{item.technical_points.map(point => <span key={point}>{point}</span>)}</div><div className="news-card-bottom"><span>{formatDate(item.primary_date)}</span><strong>{Math.round(item.score || 0)}</strong></div></button>;
}

function NewsListRow({ item, onSelect, onAction, onTechPoint }: { item: NewsItem; onSelect: (item: NewsItem) => void; onAction: (id: number, name: string) => void; onTechPoint: (point: string) => void }) {
  return <article className={`news-list-row ${item.user_state?.reading_state === 'read' ? 'read' : ''}`}><div className="row-main" role="button" tabIndex={0} onClick={() => onSelect(item)} onKeyDown={event => { if (event.key === 'Enter') onSelect(item); }}><div className="news-card-top"><Badge tone={item.item_type === 'paper' ? 'green' : 'violet'}>{typeLabel(item.item_type)}</Badge><span>{displayTopic(item)} · {item.source} · {formatDate(item.primary_date)}</span></div><h3>{displayTheme(item)}</h3>{displayTheme(item) !== item.title && <div className="original-title">{item.title}</div>}<div className="content-line"><b>宣传</b><span>{promoLine(item)}</span></div><div className="content-line highlight-line"><b>亮点</b><span>{highlightLine(item)}</span></div><div className="tag-line">{item.technical_points.map(tag => <button className="tech-tag" key={tag} onClick={event => { event.stopPropagation(); onTechPoint(tag); }}>{tag}</button>)}</div></div><div className="row-side"><strong>{Math.round(item.score || 0)}</strong><div><button title="收藏" onClick={() => onAction(item.id, 'bookmark')}><Heart size={15} fill={item.user_state?.reading_state === 'bookmarked' ? 'currentColor' : 'none'} /></button><button title="已读" onClick={() => onAction(item.id, 'read')}><Check size={15} /></button></div></div></article>;
}

function NewsDetail({ item, close, onAction }: { item: NewsItem | null; close: () => void; onAction: (id: number, name: string) => void }) {
  if (!item) return <Drawer open={false} title="" onClose={close} />;
  return <Drawer open title={displayTheme(item)} subtitle={`${typeLabel(item.item_type)} · ${displayTopic(item)} · ${item.source}`} onClose={close}><div className="news-detail"><div className="detail-actions"><button onClick={() => onAction(item.id, 'bookmark')}><Heart size={15} />收藏</button><button onClick={() => onAction(item.id, 'later')}><BookOpen size={15} />稍后阅读</button><button onClick={() => onAction(item.id, 'read')}><Check size={15} />已读</button>{item.source_url && <a href={item.source_url} target="_blank" rel="noreferrer"><ExternalLink size={15} />来源</a>}</div><div className="detail-score"><span>推荐评分</span><strong>{Math.round(item.score || 0)}</strong><p>{scoreReasons(item)}</p></div><Card><span className="detail-section-label">主题</span><h3 className="detail-theme">{displayTheme(item)}</h3>{displayTheme(item) !== item.title && <p className="original-title">{item.title}</p>}<span className="detail-section-label">宣传一句话</span><p>{promoLine(item)}</p><span className="detail-section-label">亮点一句话</span><p className="detail-highlight">{highlightLine(item)}</p><span className="detail-section-label">中文摘要</span><p>{item.summary || '暂无摘要。'}</p><span className="detail-section-label">评审意见</span><p>{reviewReason(item)}</p></Card>{item.paper && <Card><h3>论文信息</h3><dl><dt>arXiv ID</dt><dd>{item.paper.arxiv_id || '—'}</dd><dt>作者</dt><dd>{item.paper.authors.join(', ') || '—'}</dd><dt>代码地址</dt><dd>{item.paper.code_url || '—'}</dd></dl></Card>}{item.project && <Card><h3>项目指标</h3><div className="project-metrics"><span><Star size={14} />{item.project.stars}</span><span><Layers3 size={14} />{item.project.forks}</span><span>{item.project.language || '未知语言'}</span></div><dl><dt>仓库</dt><dd>{item.project.repo_full_name || '—'}</dd><dt>更新时间</dt><dd>{formatDate(item.project.updated_at)}</dd></dl></Card>}<Card><h3>技术地图定位 · {techPaths(item).length} 项</h3><div className="tech-paths">{techPaths(item).length ? techPaths(item).map(path => <div key={path}><Network size={14} /><span>{path}</span></div>) : <span>暂无技术地图定位</span>}</div><h3>全部技术点 · {item.technical_points.length} 项</h3><div className="detail-tags">{item.technical_points.length ? item.technical_points.map(point => <Badge key={point} tone="sky">{point}</Badge>) : <span>暂无技术点</span>}</div></Card><button className="promote-button" onClick={() => onAction(item.id, 'promote-to-capability')}><MessageSquare size={15} />流转到能力洞察</button></div></Drawer>;
}

function useUrlState<T extends string>(key: string, fallback: T): [T, (value: T) => void] {
  const read = () => (new URLSearchParams(window.location.search).get(key) as T) || fallback;
  const [value, setValue] = useState<T>(read);
  useEffect(() => { const onPopState = () => setValue(read()); window.addEventListener('popstate', onPopState); return () => window.removeEventListener('popstate', onPopState); }, []);
  const update = (next: T) => { setValue(next); const url = new URL(window.location.href); url.searchParams.set(key, next); window.history.pushState({}, '', url); };
  return [value, update];
}

function displayTopic(item: NewsItem): string { return String(item.payload.display_topic || '待复核'); }
function displayTheme(item: NewsItem): string { return String(item.payload.display_theme || item.title); }
function promoLine(item: NewsItem): string { return String(item.payload.one_liner || item.summary || '暂无宣传语'); }
function highlightLine(item: NewsItem): string { return String(item.highlight || item.payload.highlight_line || '暂无亮点'); }
function reviewReason(item: NewsItem): string { const review = item.payload.review; return review && typeof review === 'object' ? String((review as Record<string, unknown>).review_reason || '暂无评审意见') : '暂无评审意见'; }
function techPaths(item: NewsItem): string[] { const paths = item.payload.tech_paths; if (!Array.isArray(paths)) return []; return paths.filter(path => path && typeof path === 'object').map(path => { const value = path as Record<string, unknown>; return [value.dimension, value.category, value.point].filter(Boolean).map(String).join(' → '); }); }
function viewTitle(view: NewsView): string { return ({ today: '今日精选', all: '全部动态', reports: '日报', topics: '专题时间线' })[view]; }
function viewDescription(view: NewsView): string { return ({ today: '先看今天最值得阅读的 AI 安全论文与开源项目。', all: '检索、筛选并处理全部论文和项目动态。', reports: '按日期回顾采集结果、精选内容和主题变化。', topics: '按中文安全主题聚合资讯，并逐步扩展为事件级持续跟踪。' })[view]; }
function typeLabel(type: string): string { return type === 'paper' ? '论文' : '项目'; }
function formatDate(value: string): string { return value ? value.slice(0, 10) : '未知日期'; }
function scoreReasons(item: NewsItem): string { const scoring = item.payload.scoring; if (!scoring || typeof scoring !== 'object') return '基于相关性、安全价值、新鲜度和信息完整度综合评分。'; const reasons = (scoring as { reasons?: unknown }).reasons; return Array.isArray(reasons) ? reasons.map(String).join('；') : '基于相关性、安全价值、新鲜度和信息完整度综合评分。'; }
function toggleValue(values: string[], value: string): string[] { return values.includes(value) ? values.filter(item => item !== value) : [...values, value]; }
