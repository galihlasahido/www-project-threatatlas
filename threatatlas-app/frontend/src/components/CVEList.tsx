import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { ExternalLink, ChevronDown, ChevronUp, ShieldAlert } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface CVEItem {
  cve_id: string;
  description: string;
  cvss_v3_score: number | null;
  cvss_v3_severity: string | null;
  published_date: string | null;
  source_url: string | null;
  technology?: string;
  element_id?: string;
}

interface CVEListProps {
  cves: CVEItem[];
  loading?: boolean;
  showTechnology?: boolean;
  compact?: boolean;
}

function getSeverityColor(severity: string | null) {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL':
      return 'bg-red-100 text-red-800 border-red-300 dark:bg-red-900/40 dark:text-red-300 dark:border-red-700';
    case 'HIGH':
      return 'bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-900/40 dark:text-orange-300 dark:border-orange-700';
    case 'MEDIUM':
      return 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-900/40 dark:text-amber-300 dark:border-amber-700';
    case 'LOW':
      return 'bg-green-100 text-green-800 border-green-300 dark:bg-green-900/40 dark:text-green-300 dark:border-green-700';
    default:
      return 'bg-slate-100 text-slate-800 border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-600';
  }
}

function getScoreColor(score: number | null) {
  if (score === null) return 'text-muted-foreground';
  if (score >= 9.0) return 'text-red-600 dark:text-red-400';
  if (score >= 7.0) return 'text-orange-600 dark:text-orange-400';
  if (score >= 4.0) return 'text-amber-600 dark:text-amber-400';
  return 'text-green-600 dark:text-green-400';
}

export function CVEList({ cves, loading = false, showTechnology = false, compact = false }: CVEListProps) {
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  const toggleExpand = (cveId: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(cveId)) {
        next.delete(cveId);
      } else {
        next.add(cveId);
      }
      return next;
    });
  };

  if (loading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="space-y-2">
            <Skeleton className="h-4 w-32" />
            <Skeleton className="h-3 w-full" />
            <Skeleton className="h-3 w-3/4" />
          </div>
        ))}
      </div>
    );
  }

  if (cves.length === 0) {
    return (
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center justify-center p-8">
          <ShieldAlert className="h-10 w-10 text-muted-foreground mb-3" />
          <p className="text-sm font-medium mb-1">No CVEs found</p>
          <p className="text-xs text-muted-foreground text-center">
            No known vulnerabilities matched your criteria.
          </p>
        </CardContent>
      </Card>
    );
  }

  if (compact) {
    return (
      <div className="space-y-2">
        {cves.map((cve) => (
          <div
            key={cve.cve_id}
            className="flex items-center gap-2 p-2 rounded-lg border bg-card hover:bg-muted/30 transition-colors"
          >
            <span className={cn('text-sm font-bold tabular-nums', getScoreColor(cve.cvss_v3_score))}>
              {cve.cvss_v3_score !== null ? cve.cvss_v3_score.toFixed(1) : 'N/A'}
            </span>
            <Badge variant="outline" className={cn('text-xs shrink-0', getSeverityColor(cve.cvss_v3_severity))}>
              {cve.cvss_v3_severity || 'UNKNOWN'}
            </Badge>
            {cve.source_url ? (
              <a
                href={cve.source_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs font-mono text-primary hover:underline shrink-0"
              >
                {cve.cve_id}
              </a>
            ) : (
              <span className="text-xs font-mono shrink-0">{cve.cve_id}</span>
            )}
            <span className="text-xs text-muted-foreground truncate flex-1">
              {cve.description}
            </span>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[100px]">CVE ID</TableHead>
            <TableHead className="w-[80px]">Score</TableHead>
            <TableHead className="w-[90px]">Severity</TableHead>
            <TableHead>Description</TableHead>
            {showTechnology && <TableHead className="w-[120px]">Technology</TableHead>}
            <TableHead className="w-[100px]">Published</TableHead>
            <TableHead className="w-[40px]" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {cves.map((cve) => {
            const isExpanded = expandedRows.has(cve.cve_id);
            return (
              <TableRow key={cve.cve_id}>
                <TableCell>
                  {cve.source_url ? (
                    <a
                      href={cve.source_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs font-mono text-primary hover:underline flex items-center gap-1"
                    >
                      {cve.cve_id}
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  ) : (
                    <span className="text-xs font-mono">{cve.cve_id}</span>
                  )}
                </TableCell>
                <TableCell>
                  <span className={cn('text-sm font-bold tabular-nums', getScoreColor(cve.cvss_v3_score))}>
                    {cve.cvss_v3_score !== null ? cve.cvss_v3_score.toFixed(1) : 'N/A'}
                  </span>
                </TableCell>
                <TableCell>
                  <Badge variant="outline" className={cn('text-xs', getSeverityColor(cve.cvss_v3_severity))}>
                    {cve.cvss_v3_severity || 'UNKNOWN'}
                  </Badge>
                </TableCell>
                <TableCell>
                  <div className={cn('text-xs text-muted-foreground', !isExpanded && 'line-clamp-2')}>
                    {cve.description}
                  </div>
                  {cve.description.length > 150 && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-5 text-xs px-1 mt-1"
                      onClick={() => toggleExpand(cve.cve_id)}
                    >
                      {isExpanded ? (
                        <>
                          <ChevronUp className="h-3 w-3 mr-1" /> Less
                        </>
                      ) : (
                        <>
                          <ChevronDown className="h-3 w-3 mr-1" /> More
                        </>
                      )}
                    </Button>
                  )}
                </TableCell>
                {showTechnology && (
                  <TableCell>
                    {cve.technology && (
                      <Badge variant="secondary" className="text-xs">
                        {cve.technology}
                      </Badge>
                    )}
                  </TableCell>
                )}
                <TableCell>
                  <span className="text-xs text-muted-foreground">
                    {cve.published_date
                      ? new Date(cve.published_date).toLocaleDateString()
                      : 'N/A'}
                  </span>
                </TableCell>
                <TableCell>
                  {cve.source_url && (
                    <a
                      href={cve.source_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-muted-foreground hover:text-primary"
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                    </a>
                  )}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
