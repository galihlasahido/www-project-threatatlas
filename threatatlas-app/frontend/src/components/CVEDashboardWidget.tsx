import { useState, useEffect } from 'react';
import { cvesApi } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { ShieldAlert, ExternalLink } from 'lucide-react';
import { cn } from '@/lib/utils';

interface CVESummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  top_cves: Array<{
    cve_id: string;
    cvss_v3_score: number | null;
    cvss_v3_severity: string | null;
    description: string;
    source_url: string | null;
  }>;
}

interface CVEDashboardWidgetProps {
  productIds?: number[];
}

export function CVEDashboardWidget({ productIds }: CVEDashboardWidgetProps) {
  const [summary, setSummary] = useState<CVESummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadSummary();
  }, [productIds]);

  const loadSummary = async () => {
    try {
      setLoading(true);
      const response = await cvesApi.summary(productIds);
      setSummary(response.data);
    } catch (error) {
      console.error('Error loading CVE summary:', error);
      setSummary(null);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <Card className="hover:shadow-lg hover:border-primary/20 transition-all duration-300 rounded-xl border-border/60">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-3 pt-5">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-10 w-10 rounded-xl" />
        </CardHeader>
        <CardContent className="pb-5">
          <Skeleton className="h-8 w-16 mb-2" />
          <Skeleton className="h-3 w-24 mb-3" />
          <div className="flex gap-2">
            <Skeleton className="h-5 w-16" />
            <Skeleton className="h-5 w-16" />
            <Skeleton className="h-5 w-16" />
          </div>
        </CardContent>
      </Card>
    );
  }

  const data = summary || { total: 0, critical: 0, high: 0, medium: 0, low: 0, top_cves: [] };

  return (
    <Card className="hover:shadow-lg hover:border-primary/20 transition-all duration-300 rounded-xl border-border/60 group cursor-default">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-3 pt-5">
        <CardTitle className="text-xs font-bold text-muted-foreground tracking-wider">VULNERABILITIES</CardTitle>
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-red-500/10 shadow-sm group-hover:shadow-md transition-all duration-300 group-hover:scale-110">
          <ShieldAlert className="h-5 w-5 text-red-600 transition-transform duration-300 group-hover:rotate-12" />
        </div>
      </CardHeader>
      <CardContent className="pb-5">
        <div className="text-3xl font-bold tracking-tight mb-1 bg-gradient-to-br from-foreground to-foreground/70 bg-clip-text">
          {data.total}
        </div>
        <p className="text-xs text-muted-foreground mb-2 font-medium">Known CVEs matched</p>

        <div className="flex flex-wrap gap-1.5 mb-3">
          {data.critical > 0 && (
            <Badge variant="outline" className="text-xs bg-red-100 text-red-800 border-red-300 dark:bg-red-900/40 dark:text-red-300 dark:border-red-700">
              {data.critical} Critical
            </Badge>
          )}
          {data.high > 0 && (
            <Badge variant="outline" className="text-xs bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-900/40 dark:text-orange-300 dark:border-orange-700">
              {data.high} High
            </Badge>
          )}
          {data.medium > 0 && (
            <Badge variant="outline" className="text-xs bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-900/40 dark:text-amber-300 dark:border-amber-700">
              {data.medium} Medium
            </Badge>
          )}
          {data.low > 0 && (
            <Badge variant="outline" className="text-xs bg-green-100 text-green-800 border-green-300 dark:bg-green-900/40 dark:text-green-300 dark:border-green-700">
              {data.low} Low
            </Badge>
          )}
          {data.total === 0 && (
            <span className="text-xs text-green-600 font-semibold">No known vulnerabilities</span>
          )}
        </div>

        {data.top_cves && data.top_cves.length > 0 && (
          <div className="space-y-1.5 border-t pt-2">
            <span className="text-xs font-semibold text-muted-foreground">Top Critical</span>
            {data.top_cves.slice(0, 5).map((cve) => (
              <div key={cve.cve_id} className="flex items-center gap-2">
                <span className={cn(
                  'text-xs font-bold tabular-nums',
                  cve.cvss_v3_score && cve.cvss_v3_score >= 9 ? 'text-red-600' :
                  cve.cvss_v3_score && cve.cvss_v3_score >= 7 ? 'text-orange-600' : 'text-amber-600'
                )}>
                  {cve.cvss_v3_score?.toFixed(1) || 'N/A'}
                </span>
                {cve.source_url ? (
                  <a
                    href={cve.source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono text-primary hover:underline flex items-center gap-0.5"
                  >
                    {cve.cve_id}
                    <ExternalLink className="h-2.5 w-2.5" />
                  </a>
                ) : (
                  <span className="text-xs font-mono">{cve.cve_id}</span>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
