import { useState, useEffect } from 'react';
import { cwesApi } from '@/lib/api';
import { CWEBadge } from '@/components/CWEBadge';
import { CVEList, type CVEItem } from '@/components/CVEList';
import { Skeleton } from '@/components/ui/skeleton';
import { ChevronDown, ChevronRight } from 'lucide-react';

interface CWE {
  id: number;
  cwe_id: string;
  name: string;
  description: string;
  category: string;
  severity?: string;
}

interface CWEPanelProps {
  threatId: number;
  compact?: boolean;
}

export function CWEPanel({ threatId, compact = false }: CWEPanelProps) {
  const [cwes, setCwes] = useState<CWE[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedCwe, setExpandedCwe] = useState<number | null>(null);
  const [cveMap, setCveMap] = useState<Record<number, CVEItem[]>>({});
  const [cveLoading, setCveLoading] = useState<number | null>(null);

  useEffect(() => {
    loadCWEs();
  }, [threatId]);

  const loadCWEs = async () => {
    try {
      setLoading(true);
      const response = await cwesApi.getForThreat(threatId);
      setCwes(Array.isArray(response.data) ? response.data : []);
    } catch (error) {
      // CWE endpoint may not exist yet - silently fail
      setCwes([]);
    } finally {
      setLoading(false);
    }
  };

  const handleExpandCwe = async (cweId: number) => {
    if (expandedCwe === cweId) {
      setExpandedCwe(null);
      return;
    }

    setExpandedCwe(cweId);

    if (!cveMap[cweId]) {
      try {
        setCveLoading(cweId);
        const response = await cwesApi.getCVEs(cweId);
        setCveMap((prev) => ({
          ...prev,
          [cweId]: Array.isArray(response.data) ? response.data : [],
        }));
      } catch {
        setCveMap((prev) => ({ ...prev, [cweId]: [] }));
      } finally {
        setCveLoading(null);
      }
    }
  };

  if (loading) {
    return (
      <div className="flex gap-1">
        <Skeleton className="h-5 w-20" />
        <Skeleton className="h-5 w-24" />
      </div>
    );
  }

  if (cwes.length === 0) {
    return null;
  }

  if (compact) {
    return (
      <div className="flex flex-wrap gap-1 mt-1">
        {cwes.map((cwe) => (
          <CWEBadge
            key={cwe.id}
            cweId={cwe.cwe_id}
            name={cwe.name}
            severity={cwe.severity}
          />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold text-muted-foreground">Related CWEs</h4>
      <div className="space-y-1.5">
        {cwes.map((cwe) => (
          <div key={cwe.id}>
            <button
              className="w-full flex items-center gap-2 text-left p-2 rounded-lg hover:bg-muted/50 transition-colors"
              onClick={() => handleExpandCwe(cwe.id)}
            >
              {expandedCwe === cwe.id ? (
                <ChevronDown className="h-3 w-3 text-muted-foreground shrink-0" />
              ) : (
                <ChevronRight className="h-3 w-3 text-muted-foreground shrink-0" />
              )}
              <CWEBadge cweId={cwe.cwe_id} name={cwe.name} severity={cwe.severity} />
              {cwe.category && (
                <span className="text-xs text-muted-foreground ml-auto">{cwe.category}</span>
              )}
            </button>
            {expandedCwe === cwe.id && (
              <div className="ml-5 mt-1 mb-2">
                {cwe.description && (
                  <p className="text-xs text-muted-foreground mb-2">{cwe.description}</p>
                )}
                <CVEList
                  cves={cveMap[cwe.id] || []}
                  loading={cveLoading === cwe.id}
                  compact
                />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
