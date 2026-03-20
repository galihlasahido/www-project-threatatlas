import { useState, useEffect } from 'react';
import { cvesApi } from '@/lib/api';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';
import { Search, ShieldAlert, ExternalLink, ChevronLeft, ChevronRight, Download } from 'lucide-react';
import { cn } from '@/lib/utils';

interface Product {
  id: number;
  name: string;
}

interface VulnerabilitiesTabProps {
  products: Product[];
}

interface CVERow {
  cve_id: string;
  description: string;
  cvss_v3_score: number | null;
  cvss_v3_severity: string | null;
  published_date: string | null;
  source_url: string | null;
  technology?: string;
  product_name?: string;
  diagram_name?: string;
  element_id?: string;
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

export function VulnerabilitiesTab({ products }: VulnerabilitiesTabProps) {
  const [cves, setCves] = useState<CVERow[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [productFilter, setProductFilter] = useState<string>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(10);

  // CVE ID lookup
  const [cveIdInput, setCveIdInput] = useState('');
  const [fetching, setFetching] = useState(false);

  useEffect(() => {
    loadCVEs();
  }, [products]);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, severityFilter, productFilter]);

  const loadCVEs = async () => {
    try {
      setLoading(true);
      const productIds = products.map((p) => p.id);
      if (productIds.length === 0) {
        setCves([]);
        return;
      }
      const response = await cvesApi.summary(productIds);
      const data = response.data;
      // The summary endpoint may return all_cves or we get from list
      if (data?.all_cves && Array.isArray(data.all_cves)) {
        setCves(data.all_cves);
      } else {
        // Try fetching from the list endpoint
        const listRes = await cvesApi.list({ limit: 200 });
        setCves(Array.isArray(listRes.data) ? listRes.data : listRes.data?.results || []);
      }
    } catch (error) {
      console.error('Error loading CVEs:', error);
      setCves([]);
    } finally {
      setLoading(false);
    }
  };

  const handleFetchCVE = async () => {
    if (!cveIdInput.trim()) return;

    try {
      setFetching(true);
      const response = await cvesApi.search({
        keyword: cveIdInput.trim(),
        fetch_from_nvd: true,
      });
      const results = Array.isArray(response.data) ? response.data : response.data?.results || [];
      if (results.length > 0) {
        // Add to list without duplicates
        setCves((prev) => {
          const existingIds = new Set(prev.map((c) => c.cve_id));
          const newCves = results.filter((c: CVERow) => !existingIds.has(c.cve_id));
          return [...newCves, ...prev];
        });
      }
      setCveIdInput('');
    } catch (error) {
      console.error('Error fetching CVE:', error);
    } finally {
      setFetching(false);
    }
  };

  const filteredCves = cves.filter((cve) => {
    const matchesSearch =
      searchTerm === '' ||
      cve.cve_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      cve.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (cve.technology || '').toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity =
      severityFilter === 'all' || cve.cvss_v3_severity?.toUpperCase() === severityFilter.toUpperCase();

    const matchesProduct =
      productFilter === 'all' || cve.product_name === productFilter;

    return matchesSearch && matchesSeverity && matchesProduct;
  });

  const totalPages = Math.ceil(filteredCves.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const paginatedCves = filteredCves.slice(startIndex, startIndex + itemsPerPage);

  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Filters Row */}
      <Card className="border-border/60 rounded-xl shadow-sm">
        <CardContent className="p-5">
          <div className="flex flex-col gap-3 md:flex-row md:items-center">
            <div className="relative flex-1 group">
              <Search className="absolute left-3.5 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground group-focus-within:text-primary transition-colors" />
              <Input
                placeholder="Search CVEs, descriptions, technologies..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 h-10 rounded-lg border-border/60"
              />
            </div>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-40 h-10 rounded-lg border-border/60">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="CRITICAL">Critical</SelectItem>
                <SelectItem value="HIGH">High</SelectItem>
                <SelectItem value="MEDIUM">Medium</SelectItem>
                <SelectItem value="LOW">Low</SelectItem>
              </SelectContent>
            </Select>
            <Select value={productFilter} onValueChange={setProductFilter}>
              <SelectTrigger className="w-44 h-10 rounded-lg border-border/60">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Products</SelectItem>
                {products.map((p) => (
                  <SelectItem key={p.id} value={p.name}>
                    {p.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Fetch CVE by ID */}
          <div className="flex items-center gap-2 mt-3 pt-3 border-t border-border/40">
            <Input
              value={cveIdInput}
              onChange={(e) => setCveIdInput(e.target.value)}
              placeholder="Enter CVE ID (e.g., CVE-2024-1234)"
              className="w-64 h-9 text-sm"
              onKeyDown={(e) => e.key === 'Enter' && handleFetchCVE()}
            />
            <Button
              size="sm"
              variant="outline"
              onClick={handleFetchCVE}
              disabled={fetching || !cveIdInput.trim()}
              className="h-9"
            >
              <Download className="h-3.5 w-3.5 mr-1" />
              {fetching ? 'Fetching...' : 'Fetch from NVD'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* CVE Table */}
      {filteredCves.length === 0 ? (
        <Card className="border-dashed border-2 rounded-xl">
          <CardContent className="flex flex-col items-center justify-center p-12">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-slate-500/10 to-slate-500/5 mb-3 shadow-sm">
              <ShieldAlert className="h-8 w-8 text-muted-foreground" />
            </div>
            <h3 className="text-lg font-bold mb-1.5">No vulnerabilities found</h3>
            <p className="text-sm text-muted-foreground text-center max-w-sm leading-relaxed">
              Add technology tags to your diagram elements to start matching CVEs from the NVD database.
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          <Card className="border-border/60 rounded-xl shadow-sm">
            <CardContent className="p-0">
              <div className="rounded-lg overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[130px]">CVE ID</TableHead>
                      <TableHead className="w-[70px]">Score</TableHead>
                      <TableHead className="w-[90px]">Severity</TableHead>
                      <TableHead>Description</TableHead>
                      <TableHead className="w-[110px]">Technology</TableHead>
                      <TableHead className="w-[100px]">Product</TableHead>
                      <TableHead className="w-[100px]">Published</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {paginatedCves.map((cve) => (
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
                          <p className="text-xs text-muted-foreground line-clamp-2">
                            {cve.description}
                          </p>
                        </TableCell>
                        <TableCell>
                          {cve.technology && (
                            <Badge variant="secondary" className="text-xs">
                              {cve.technology}
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          {cve.product_name && (
                            <span className="text-xs text-muted-foreground">{cve.product_name}</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <span className="text-xs text-muted-foreground">
                            {cve.published_date
                              ? new Date(cve.published_date).toLocaleDateString()
                              : 'N/A'}
                          </span>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>

          {/* Pagination */}
          {totalPages > 1 && (
            <Card className="border-border/60 rounded-xl shadow-sm">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="text-sm text-muted-foreground font-medium">
                    Showing {startIndex + 1}-{Math.min(startIndex + itemsPerPage, filteredCves.length)} of {filteredCves.length}
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setCurrentPage((prev) => Math.max(1, prev - 1))}
                      disabled={currentPage === 1}
                      className="h-9 px-3 rounded-lg"
                    >
                      <ChevronLeft className="h-4 w-4 mr-1" />
                      Previous
                    </Button>
                    <div className="flex items-center gap-1">
                      {Array.from({ length: totalPages }, (_, i) => i + 1)
                        .filter((page) => page === 1 || page === totalPages || (page >= currentPage - 1 && page <= currentPage + 1))
                        .map((page, idx, arr) => (
                          <div key={page} className="flex items-center">
                            {idx > 0 && page - arr[idx - 1] > 1 && (
                              <span className="px-2 text-muted-foreground">...</span>
                            )}
                            <Button
                              variant={currentPage === page ? 'default' : 'outline'}
                              size="sm"
                              onClick={() => setCurrentPage(page)}
                              className={cn('h-9 w-9 p-0 rounded-lg', currentPage === page && 'shadow-md')}
                            >
                              {page}
                            </Button>
                          </div>
                        ))}
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setCurrentPage((prev) => Math.min(totalPages, prev + 1))}
                      disabled={currentPage === totalPages}
                      className="h-9 px-3 rounded-lg"
                    >
                      Next
                      <ChevronRight className="h-4 w-4 ml-1" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
