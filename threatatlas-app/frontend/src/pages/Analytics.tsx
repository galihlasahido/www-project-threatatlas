import { useState, useEffect } from 'react';
import { productsApi, diagramsApi, analyticsApi } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { AlertTriangle, Shield, TrendingUp, Bug } from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import ChartCard from '@/components/analytics/ChartCard';
import RiskHeatmap from '@/components/analytics/RiskHeatmap';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

const STATUS_COLORS: Record<string, string> = {
  identified: '#3b82f6',
  mitigated: '#22c55e',
  accepted: '#eab308',
};

const PIE_COLORS = ['#3b82f6', '#22c55e', '#eab308', '#ef4444', '#8b5cf6', '#f97316'];

interface SummaryData {
  total_threats: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  mitigation_coverage: number;
  average_risk_score: number;
  total_cves: number;
}

export default function Analytics() {
  const [products, setProducts] = useState<any[]>([]);
  const [diagrams, setDiagrams] = useState<any[]>([]);
  const [selectedProduct, setSelectedProduct] = useState<string>('all');
  const [selectedDiagram, setSelectedDiagram] = useState<string>('all');
  const [loading, setLoading] = useState(true);

  const [summary, setSummary] = useState<SummaryData | null>(null);
  const [heatmapData, setHeatmapData] = useState<any[]>([]);
  const [categoryData, setCategoryData] = useState<any[]>([]);
  const [statusData, setStatusData] = useState<any[]>([]);
  const [severityData, setSeverityData] = useState<any[]>([]);
  const [cveSeverityData, setCveSeverityData] = useState<any[]>([]);
  const [techVulnData, setTechVulnData] = useState<any[]>([]);

  useEffect(() => {
    loadProducts();
  }, []);

  useEffect(() => {
    if (selectedProduct !== 'all') {
      loadDiagrams(Number(selectedProduct));
    } else {
      setDiagrams([]);
      setSelectedDiagram('all');
    }
  }, [selectedProduct]);

  useEffect(() => {
    loadAnalytics();
  }, [selectedProduct, selectedDiagram]);

  const loadProducts = async () => {
    try {
      const res = await productsApi.list();
      setProducts(res.data);
    } catch (error) {
      console.error('Error loading products:', error);
    }
  };

  const loadDiagrams = async (productId: number) => {
    try {
      const res = await diagramsApi.list({ product_id: productId });
      setDiagrams(res.data);
    } catch (error) {
      console.error('Error loading diagrams:', error);
    }
  };

  const loadAnalytics = async () => {
    setLoading(true);
    const params: { product_id?: number; diagram_id?: number } = {};
    if (selectedProduct !== 'all') params.product_id = Number(selectedProduct);
    if (selectedDiagram !== 'all') params.diagram_id = Number(selectedDiagram);

    try {
      const [summaryRes, heatmapRes, categoryRes, statusRes, severityRes, cveRes, techRes] =
        await Promise.all([
          analyticsApi.summary(params),
          analyticsApi.riskHeatmap(params),
          analyticsApi.categoryDistribution(params),
          analyticsApi.statusDistribution(params),
          analyticsApi.severityDistribution(params),
          analyticsApi.cveSeverity(params.product_id ? { product_id: params.product_id } : undefined),
          analyticsApi.techVulnerability(params.product_id ? { product_id: params.product_id, diagram_id: params.diagram_id } : undefined),
        ]);

      // Map backend field names to frontend interface
      const raw = summaryRes.data;
      const bySev = raw.threats_by_severity || {};
      const totalCves = Array.isArray(cveRes.data)
        ? cveRes.data.reduce((sum: number, d: any) => sum + (d.count || 0), 0)
        : 0;
      setSummary({
        total_threats: raw.total_threats || 0,
        critical_count: bySev.critical || 0,
        high_count: bySev.high || 0,
        medium_count: bySev.medium || 0,
        low_count: bySev.low || 0,
        mitigation_coverage: raw.mitigation_coverage || 0,
        average_risk_score: raw.avg_risk_score || 0,
        total_cves: totalCves,
      });
      setHeatmapData(heatmapRes.data);
      setCategoryData(categoryRes.data);
      setStatusData(statusRes.data);
      setSeverityData(severityRes.data);
      setCveSeverityData(cveRes.data);
      setTechVulnData(techRes.data);
    } catch (error) {
      console.error('Error loading analytics:', error);
    } finally {
      setLoading(false);
    }
  };

  const getRiskRating = (score: number): { label: string; color: string } => {
    if (score >= 20) return { label: 'Critical', color: 'text-red-600' };
    if (score >= 12) return { label: 'High', color: 'text-orange-600' };
    if (score >= 6) return { label: 'Medium', color: 'text-yellow-600' };
    return { label: 'Low', color: 'text-green-600' };
  };

  const coverageColor = (pct: number): string => {
    if (pct >= 80) return 'text-green-600';
    if (pct >= 50) return 'text-yellow-600';
    return 'text-red-600';
  };

  const statCards = summary
    ? [
        {
          title: 'Total Threats',
          value: summary.total_threats,
          icon: AlertTriangle,
          color: 'text-orange-600',
          bgColor: 'bg-orange-500/10',
          extra: (
            <div className="flex flex-wrap gap-1 mt-2">
              {summary.critical_count > 0 && <Badge variant="outline" className="text-xs bg-red-50 text-red-700 border-red-200">{summary.critical_count} Critical</Badge>}
              {summary.high_count > 0 && <Badge variant="outline" className="text-xs bg-orange-50 text-orange-700 border-orange-200">{summary.high_count} High</Badge>}
              {summary.medium_count > 0 && <Badge variant="outline" className="text-xs bg-yellow-50 text-yellow-700 border-yellow-200">{summary.medium_count} Medium</Badge>}
              {summary.low_count > 0 && <Badge variant="outline" className="text-xs bg-green-50 text-green-700 border-green-200">{summary.low_count} Low</Badge>}
            </div>
          ),
        },
        {
          title: 'Mitigation Coverage',
          value: `${Math.round(summary.mitigation_coverage)}%`,
          icon: Shield,
          color: coverageColor(summary.mitigation_coverage),
          bgColor: 'bg-green-500/10',
          extra: (
            <div className="mt-2 w-full bg-muted rounded-full h-2">
              <div
                className={`h-2 rounded-full transition-all ${summary.mitigation_coverage >= 80 ? 'bg-green-500' : summary.mitigation_coverage >= 50 ? 'bg-yellow-500' : 'bg-red-500'}`}
                style={{ width: `${Math.min(summary.mitigation_coverage, 100)}%` }}
              />
            </div>
          ),
        },
        {
          title: 'Average Risk Score',
          value: summary.average_risk_score.toFixed(1),
          icon: TrendingUp,
          color: getRiskRating(summary.average_risk_score).color,
          bgColor: 'bg-blue-500/10',
          extra: (
            <Badge variant="outline" className={`mt-2 text-xs ${getRiskRating(summary.average_risk_score).color}`}>
              {getRiskRating(summary.average_risk_score).label} Risk
            </Badge>
          ),
        },
        {
          title: 'Total CVEs Found',
          value: summary.total_cves,
          icon: Bug,
          color: 'text-purple-600',
          bgColor: 'bg-purple-500/10',
          extra: null,
        },
      ]
    : [];

  return (
    <div className="flex-1 space-y-6 mx-auto p-4">
      {/* Filter Bar */}
      <Card className="border-border/60 rounded-xl shadow-sm">
        <CardContent className="p-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <Select value={selectedProduct} onValueChange={(v) => { setSelectedProduct(v); setSelectedDiagram('all'); }}>
              <SelectTrigger className="w-56 h-10 rounded-lg">
                <SelectValue placeholder="All Products" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Products</SelectItem>
                {products.map((p) => (
                  <SelectItem key={p.id} value={String(p.id)}>{p.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select
              value={selectedDiagram}
              onValueChange={setSelectedDiagram}
              disabled={selectedProduct === 'all'}
            >
              <SelectTrigger className="w-56 h-10 rounded-lg">
                <SelectValue placeholder="All Diagrams" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Diagrams</SelectItem>
                {diagrams.map((d) => (
                  <SelectItem key={d.id} value={String(d.id)}>{d.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Stats Cards */}
      {loading ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[1, 2, 3, 4].map((i) => (
            <Card key={i} className="rounded-xl">
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-24" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-8 w-16 mb-2" />
                <Skeleton className="h-4 w-32" />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : summary ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {statCards.map((stat, index) => (
            <Card
              key={stat.title}
              className="hover:shadow-lg hover:border-primary/20 transition-all duration-300 rounded-xl border-border/60 group cursor-default"
              style={{
                animation: 'slideUp 0.5s ease-out forwards',
                animationDelay: `${index * 100}ms`,
                opacity: 0,
              }}
            >
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2 pt-5">
                <CardTitle className="text-xs font-bold text-muted-foreground tracking-wider">
                  {stat.title.toUpperCase()}
                </CardTitle>
                <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${stat.bgColor} shadow-sm`}>
                  <stat.icon className={`h-5 w-5 ${stat.color}`} />
                </div>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold tracking-tight mb-1">{stat.value}</div>
                {stat.extra}
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <Card className="border-dashed rounded-xl">
          <CardContent className="flex items-center justify-center p-12">
            <p className="text-sm text-muted-foreground">No analytics data available.</p>
          </CardContent>
        </Card>
      )}

      {/* Charts Grid */}
      <div className="grid gap-4 md:grid-cols-2">
        {/* Risk Heat Map */}
        <ChartCard title="Risk Heat Map" description="Threat distribution by likelihood and impact" loading={loading}>
          {heatmapData.length > 0 ? (
            <RiskHeatmap data={heatmapData} />
          ) : (
            <div className="flex items-center justify-center h-[250px] text-sm text-muted-foreground">
              No risk data available
            </div>
          )}
        </ChartCard>

        {/* Threat Categories (STRIDE) */}
        <ChartCard title="Threat Categories" description="Distribution by STRIDE category" loading={loading}>
          {categoryData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={categoryData}>
                <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
                <XAxis dataKey="category" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} />
                <Tooltip />
                <Legend />
                <Bar dataKey="count" name="Threats" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[300px] text-sm text-muted-foreground">
              No category data available
            </div>
          )}
        </ChartCard>

        {/* Threat Status */}
        <ChartCard title="Threat Status" description="Current status distribution" loading={loading}>
          {statusData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={statusData}
                  cx="50%"
                  cy="50%"
                  labelLine={true}
                  label={({ name, value }) => `${name} (${value})`}
                  outerRadius={100}
                  fill="#8884d8"
                  dataKey="count"
                  nameKey="status"
                >
                  {statusData.map((entry: any) => (
                    <Cell
                      key={`cell-${entry.status}`}
                      fill={STATUS_COLORS[entry.status] || PIE_COLORS[statusData.indexOf(entry) % PIE_COLORS.length]}
                    />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[300px] text-sm text-muted-foreground">
              No status data available
            </div>
          )}
        </ChartCard>

        {/* Severity Distribution */}
        <ChartCard title="Severity Distribution" description="Threats by severity level" loading={loading}>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
                <XAxis dataKey="severity" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} />
                <Tooltip />
                <Bar dataKey="count" name="Threats" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry: any) => (
                    <Cell
                      key={`cell-${entry.severity}`}
                      fill={SEVERITY_COLORS[entry.severity] || '#94a3b8'}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[300px] text-sm text-muted-foreground">
              No severity data available
            </div>
          )}
        </ChartCard>

        {/* CVE Severity */}
        <ChartCard title="CVE Severity" description="CVE distribution by severity" loading={loading}>
          {cveSeverityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={cveSeverityData}
                  cx="50%"
                  cy="50%"
                  labelLine={true}
                  label={({ name, value }) => `${name} (${value})`}
                  outerRadius={100}
                  fill="#8884d8"
                  dataKey="count"
                  nameKey="severity"
                >
                  {cveSeverityData.map((entry: any, index: number) => (
                    <Cell
                      key={`cell-${entry.severity}`}
                      fill={SEVERITY_COLORS[entry.severity?.toLowerCase()] || PIE_COLORS[index % PIE_COLORS.length]}
                    />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[300px] text-sm text-muted-foreground">
              No CVE data available
            </div>
          )}
        </ChartCard>

        {/* Technology Vulnerabilities */}
        <ChartCard title="Technology Vulnerabilities" description="CVE counts per technology" loading={loading}>
          {techVulnData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={techVulnData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
                <XAxis type="number" tick={{ fontSize: 12 }} />
                <YAxis dataKey="technology" type="category" tick={{ fontSize: 11 }} width={120} />
                <Tooltip />
                <Bar dataKey="cve_count" name="CVEs" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[300px] text-sm text-muted-foreground">
              No technology vulnerability data available
            </div>
          )}
        </ChartCard>
      </div>
    </div>
  );
}
