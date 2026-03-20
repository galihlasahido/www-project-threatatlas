import { useState, useEffect } from 'react';
import { productsApi, diagramsApi, reportsApi, pentestsApi, pentestReportsApi, pentestFindingsApi } from '@/lib/api';
import { exportReportToPdf } from '@/lib/pdfExport';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { FileText, Download, Loader2, Crosshair, Shield } from 'lucide-react';
import { cn } from '@/lib/utils';
import { ReportDiagram } from '@/components/ReportDiagram';

interface ThreatItem {
  id: number;
  threat_name: string;
  category: string;
  element_id: string;
  likelihood: number | null;
  impact: number | null;
  risk_score: number | null;
  severity: string | null;
  status: string;
}

interface MitigationItem {
  id: number;
  mitigation_name: string;
  element_id: string;
  status: string;
  linked_threats: string[];
}

interface CveItem {
  cve_id: string;
  cvss_score: number | null;
  severity: string | null;
  description: string;
  technology: string;
}

interface CweItem {
  cwe_id: string;
  name: string;
  threats: string[];
}

interface DiagramInfo {
  id: number;
  name: string;
  nodes: Array<{ id: string; data: { label: string; type: string }; position: { x: number; y: number }; style?: { width?: number; height?: number } }>;
  edges: Array<{ id: string; source: string; target: string; label?: string }>;
}

interface ReportData {
  product_name: string;
  generated_at: string;
  summary: {
    total_threats: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    mitigation_coverage: number;
    overall_risk_rating: string;
    total_cves: number;
  };
  diagrams: DiagramInfo[];
  threats: ThreatItem[];
  mitigations: MitigationItem[];
  cves: CveItem[];
  cwes: CweItem[];
}

function getSeverityBadgeClass(severity: string | null): string {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'bg-red-100 text-red-800 border-red-200';
    case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
    case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
    case 'low': return 'bg-green-100 text-green-800 border-green-200';
    default: return 'bg-gray-100 text-gray-800 border-gray-200';
  }
}

function getStatusBadgeClass(status: string): string {
  switch (status) {
    case 'mitigated': case 'verified': case 'implemented': return 'bg-green-100 text-green-800 border-green-200';
    case 'identified': return 'bg-blue-100 text-blue-800 border-blue-200';
    case 'accepted': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
    default: return 'bg-gray-100 text-gray-800 border-gray-200';
  }
}

function getRiskRatingClass(rating: string): string {
  switch (rating?.toLowerCase()) {
    case 'critical': return 'bg-red-600 text-white';
    case 'high': return 'bg-orange-500 text-white';
    case 'medium': return 'bg-yellow-500 text-white';
    case 'low': return 'bg-green-500 text-white';
    default: return 'bg-gray-500 text-white';
  }
}


export default function Reports() {
  const [products, setProducts] = useState<any[]>([]);
  const [diagrams, setDiagrams] = useState<any[]>([]);
  const [selectedProduct, setSelectedProduct] = useState<string>('');
  const [selectedDiagram, setSelectedDiagram] = useState<string>('all');
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [report, setReport] = useState<ReportData | null>(null);

  // Pentest report state
  const [pentests, setPentests] = useState<any[]>([]);
  const [selectedPentestProduct, setSelectedPentestProduct] = useState<string>('');
  const [selectedPentest, setSelectedPentest] = useState<string>('all');
  const [pentestReport, setPentestReport] = useState<any>(null);
  const [pentestLoading, setPentestLoading] = useState(false);
  const [pentestExporting, setPentestExporting] = useState(false);

  useEffect(() => {
    loadProducts();
  }, []);

  useEffect(() => {
    if (selectedProduct) {
      loadDiagrams(Number(selectedProduct));
    } else {
      setDiagrams([]);
      setSelectedDiagram('all');
    }
  }, [selectedProduct]);

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

  useEffect(() => {
    if (selectedPentestProduct) {
      loadPentests(Number(selectedPentestProduct));
    } else {
      setPentests([]);
      setSelectedPentest('all');
    }
  }, [selectedPentestProduct]);

  const loadPentests = async (productId: number) => {
    try {
      const res = await pentestsApi.list({ product_id: productId });
      setPentests(res.data || []);
    } catch (error) {
      console.error('Error loading pentests:', error);
    }
  };

  const generatePentestReport = async () => {
    if (!selectedPentestProduct) return;
    setPentestLoading(true);
    setPentestReport(null);
    try {
      const params: { product_id: number; pentest_id?: number } = {
        product_id: Number(selectedPentestProduct),
      };
      if (selectedPentest !== 'all') {
        params.pentest_id = Number(selectedPentest);
      }
      const res = await pentestReportsApi.generate(params);
      setPentestReport(res.data);
    } catch (error) {
      console.error('Error generating pentest report:', error);
    } finally {
      setPentestLoading(false);
    }
  };

  const generateReport = async () => {
    if (!selectedProduct) return;
    setLoading(true);
    setReport(null);
    try {
      const params: { product_id: number; diagram_id?: number } = {
        product_id: Number(selectedProduct),
      };
      if (selectedDiagram !== 'all') {
        params.diagram_id = Number(selectedDiagram);
      }
      const res = await reportsApi.threatModel(params);
      const raw = res.data;

      // Flatten diagrams into flat threat/mitigation/cwe lists
      const allThreats: ThreatItem[] = [];
      const allMitigations: MitigationItem[] = [];
      const cweSet = new Map<string, CweItem>();

      for (const diagram of raw.diagrams || []) {
        for (const t of diagram.threats || []) {
          allThreats.push({
            id: t.id,
            threat_name: t.threat_name || 'Unknown',
            category: t.category,
            element_id: t.element_id,
            status: t.status,
            likelihood: t.likelihood,
            impact: t.impact,
            risk_score: t.risk_score,
            severity: t.severity,
          });
          for (const cweId of t.cwes || []) {
            if (!cweSet.has(cweId)) {
              cweSet.set(cweId, { cwe_id: cweId, name: cweId, threats: [t.threat_name || 'Unknown'] });
            } else {
              cweSet.get(cweId)!.threats.push(t.threat_name || 'Unknown');
            }
          }
        }
        for (const m of diagram.mitigations || []) {
          allMitigations.push({
            id: m.id,
            mitigation_name: m.mitigation_name || 'Unknown',
            element_id: m.element_id,
            status: m.status,
            linked_threats: m.linked_threats || [],
          });
        }
      }

      // Fetch diagram data for visualization
      const diagramInfos: DiagramInfo[] = [];
      for (const d of raw.diagrams || []) {
        try {
          const diagRes = await diagramsApi.get(d.diagram_id);
          const dd = diagRes.data.diagram_data || { nodes: [], edges: [] };
          diagramInfos.push({
            id: d.diagram_id,
            name: d.diagram_name,
            nodes: dd.nodes || [],
            edges: dd.edges || [],
          });
        } catch { /* skip if diagram can't be loaded */ }
      }

      // Map backend executive_summary to frontend summary
      const es = raw.executive_summary || {};
      setReport({
        product_name: raw.product_name,
        generated_at: raw.generated_at,
        diagrams: diagramInfos,
        summary: {
          total_threats: es.total_threats || 0,
          critical_count: es.critical_threats || 0,
          high_count: es.high_threats || 0,
          medium_count: es.medium_threats || 0,
          low_count: es.low_threats || 0,
          mitigation_coverage: es.mitigation_coverage || 0,
          overall_risk_rating: es.risk_rating || 'Unknown',
          total_cves: es.total_cves || 0,
        },
        threats: allThreats,
        mitigations: allMitigations,
        cves: (raw.cves || []).map((c: any) => ({
          cve_id: c.cve_id,
          cvss_score: c.cvss_v3_score,
          severity: c.cvss_v3_severity,
          description: c.description,
          technology: c.technology,
        })),
        cwes: Array.from(cweSet.values()),
      });
    } catch (error) {
      console.error('Error generating report:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleExportPdf = async () => {
    if (!report) return;
    setExporting(true);
    try {
      // Small delay to ensure ReactFlow edges finish rendering
      await new Promise(r => setTimeout(r, 500));
      const date = new Date().toISOString().split('T')[0];
      const productName = report.product_name.replace(/\s+/g, '_');
      await exportReportToPdf('report-content', `ThreatModel_${productName}_${date}.pdf`, report);
    } catch (error) {
      console.error('Error exporting PDF:', error);
    } finally {
      setExporting(false);
    }
  };

  const sortedThreats = report?.threats
    ? [...report.threats].sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0))
    : [];

  return (
    <div className="flex-1 space-y-6 mx-auto p-4">
      <Tabs defaultValue="threat-model" className="space-y-4">
        <TabsList>
          <TabsTrigger value="threat-model">
            <Shield className="h-4 w-4 mr-1.5" />
            Threat Model
          </TabsTrigger>
          <TabsTrigger value="pentest">
            <Crosshair className="h-4 w-4 mr-1.5" />
            Pentest
          </TabsTrigger>
        </TabsList>

        <TabsContent value="threat-model" className="space-y-6">
      {/* Controls Bar */}
      <Card className="border-border/60 rounded-xl shadow-sm">
        <CardContent className="p-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <Select value={selectedProduct} onValueChange={(v) => { setSelectedProduct(v); setSelectedDiagram('all'); setReport(null); }}>
              <SelectTrigger className="w-56 h-10 rounded-lg">
                <SelectValue placeholder="Select Product" />
              </SelectTrigger>
              <SelectContent>
                {products.map((p) => (
                  <SelectItem key={p.id} value={String(p.id)}>{p.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select
              value={selectedDiagram}
              onValueChange={(v) => { setSelectedDiagram(v); setReport(null); }}
              disabled={!selectedProduct}
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

            <Button
              onClick={generateReport}
              disabled={!selectedProduct || loading}
              className="h-10 rounded-lg"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Generating...
                </>
              ) : (
                <>
                  <FileText className="h-4 w-4 mr-2" />
                  Generate Report
                </>
              )}
            </Button>

            <Button
              variant="outline"
              onClick={handleExportPdf}
              disabled={!report || exporting}
              className="h-10 rounded-lg"
            >
              {exporting ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Exporting...
                </>
              ) : (
                <>
                  <Download className="h-4 w-4 mr-2" />
                  Export PDF
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Loading State */}
      {loading && (
        <Card className="border-dashed rounded-xl">
          <CardContent className="flex items-center justify-center p-16">
            <div className="flex flex-col items-center gap-3">
              <div className="h-10 w-10 animate-spin rounded-full border-4 border-primary border-t-transparent" />
              <p className="text-sm text-muted-foreground font-medium">Generating report...</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Empty State */}
      {!loading && !report && (
        <Card className="border-dashed border-2 rounded-xl">
          <CardContent className="flex flex-col items-center justify-center p-16">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-primary/10 to-primary/5 mb-3 shadow-sm">
              <FileText className="h-8 w-8 text-primary" />
            </div>
            <h3 className="text-lg font-bold mb-1.5">No Report Generated</h3>
            <p className="text-sm text-muted-foreground text-center max-w-sm leading-relaxed">
              Select a product and click "Generate Report" to create a threat model report.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Report Content */}
      {report && !loading && (
        <div id="report-content" className="bg-white text-black p-8 space-y-8 rounded-xl border">
          {/* Cover Section */}
          <div className="border-b-2 border-gray-300 pb-8 mb-8">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">THREAT MODEL REPORT</h1>
            <div className="h-1 w-24 bg-blue-600 mb-6" />
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-gray-500 font-medium">Product:</span>
                <span className="ml-2 font-semibold text-gray-900">{report.product_name}</span>
              </div>
              <div>
                <span className="text-gray-500 font-medium">Generated:</span>
                <span className="ml-2 font-semibold text-gray-900">
                  {new Date(report.generated_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}
                </span>
              </div>
              <div>
                <span className="text-gray-500 font-medium">Classification:</span>
                <span className="ml-2 font-semibold text-red-700">CONFIDENTIAL</span>
              </div>
            </div>
          </div>

          {/* Executive Summary */}
          <div>
            <h2 className="text-xl font-bold text-gray-900 mb-4">Executive Summary</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Card className="border border-gray-200 shadow-none">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-gray-900">{report.summary.total_threats}</div>
                  <div className="text-xs text-gray-500 mt-1">Total Threats</div>
                  <div className="text-xs text-gray-600 mt-1">
                    {report.summary.critical_count} Critical, {report.summary.high_count} High
                  </div>
                </CardContent>
              </Card>
              <Card className="border border-gray-200 shadow-none">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-gray-900">{Math.round(report.summary.mitigation_coverage)}%</div>
                  <div className="text-xs text-gray-500 mt-1">Mitigation Coverage</div>
                </CardContent>
              </Card>
              <Card className="border border-gray-200 shadow-none">
                <CardContent className="p-4 text-center">
                  <Badge className={cn('text-sm px-3 py-1', getRiskRatingClass(report.summary.overall_risk_rating))}>
                    {report.summary.overall_risk_rating}
                  </Badge>
                  <div className="text-xs text-gray-500 mt-2">Overall Risk Rating</div>
                </CardContent>
              </Card>
              <Card className="border border-gray-200 shadow-none">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-gray-900">{report.summary.total_cves}</div>
                  <div className="text-xs text-gray-500 mt-1">Total CVEs</div>
                </CardContent>
              </Card>
            </div>
          </div>

          {/* Data Flow Diagrams */}
          {report.diagrams && report.diagrams.length > 0 && (
            <div>
              <h2 className="text-xl font-bold text-gray-900 mb-4">Data Flow Diagrams</h2>
              {report.diagrams.map((diagram) => (
                <div key={diagram.id} className="mb-6">
                  <h3 className="text-sm font-semibold text-gray-700 mb-2">{diagram.name}</h3>
                  <div className="border border-gray-200 rounded-lg overflow-hidden bg-white" data-diagram-svg>
                    <ReportDiagram
                      nodes={diagram.nodes}
                      edges={diagram.edges}
                      height={480}
                    />
                  </div>
                  <div className="flex gap-4 mt-2 text-xs text-gray-500">
                    <span className="flex items-center gap-1"><span className="inline-block w-3 h-3 rounded-full bg-blue-200 border border-blue-500" /> Process</span>
                    <span className="flex items-center gap-1"><span className="inline-block w-3 h-3 bg-yellow-100 border border-yellow-500" /> Data Store</span>
                    <span className="flex items-center gap-1"><span className="inline-block w-3 h-3 rounded bg-pink-100 border border-pink-500" /> External Entity</span>
                    <span className="flex items-center gap-1"><span className="inline-block w-3 h-3 bg-gray-100 border border-gray-400 border-dashed" /> Trust Boundary</span>
                    <span className="flex items-center gap-1"><span className="inline-block w-6 h-0 border-t border-gray-400" />→ Data Flow</span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Threat Summary Table */}
          {sortedThreats.length > 0 && (
            <div>
              <h2 className="text-xl font-bold text-gray-900 mb-4">Threat Summary</h2>
              <div className="border rounded-lg overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow className="bg-gray-50">
                      <TableHead className="text-gray-700 font-semibold w-10">#</TableHead>
                      <TableHead className="text-gray-700 font-semibold">Threat</TableHead>
                      <TableHead className="text-gray-700 font-semibold">Category</TableHead>
                      <TableHead className="text-gray-700 font-semibold">Element</TableHead>
                      <TableHead className="text-gray-700 font-semibold text-center">Risk Score</TableHead>
                      <TableHead className="text-gray-700 font-semibold text-center">Severity</TableHead>
                      <TableHead className="text-gray-700 font-semibold text-center">Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {sortedThreats.map((threat, idx) => (
                      <TableRow key={threat.id} className="border-b border-gray-100">
                        <TableCell className="text-gray-500 text-xs">{idx + 1}</TableCell>
                        <TableCell className="font-medium text-gray-900 text-sm">{threat.threat_name}</TableCell>
                        <TableCell className="text-gray-600 text-sm">{threat.category}</TableCell>
                        <TableCell className="text-gray-600 text-sm font-mono text-xs">{threat.element_id}</TableCell>
                        <TableCell className="text-center font-bold text-sm">{threat.risk_score ?? '-'}</TableCell>
                        <TableCell className="text-center">
                          <Badge variant="outline" className={cn('text-xs capitalize', getSeverityBadgeClass(threat.severity))}>
                            {threat.severity ?? 'N/A'}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-center">
                          <Badge variant="outline" className={cn('text-xs capitalize', getStatusBadgeClass(threat.status))}>
                            {threat.status}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </div>
          )}

          {/* Mitigation Status Table */}
          {report.mitigations && report.mitigations.length > 0 && (
            <div>
              <h2 className="text-xl font-bold text-gray-900 mb-4">Mitigation Status</h2>
              <div className="border rounded-lg overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow className="bg-gray-50">
                      <TableHead className="text-gray-700 font-semibold w-10">#</TableHead>
                      <TableHead className="text-gray-700 font-semibold">Mitigation</TableHead>
                      <TableHead className="text-gray-700 font-semibold">Element</TableHead>
                      <TableHead className="text-gray-700 font-semibold text-center">Status</TableHead>
                      <TableHead className="text-gray-700 font-semibold">Linked Threats</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {report.mitigations.map((mit, idx) => (
                      <TableRow key={mit.id} className="border-b border-gray-100">
                        <TableCell className="text-gray-500 text-xs">{idx + 1}</TableCell>
                        <TableCell className="font-medium text-gray-900 text-sm">{mit.mitigation_name}</TableCell>
                        <TableCell className="text-gray-600 text-sm font-mono text-xs">{mit.element_id}</TableCell>
                        <TableCell className="text-center">
                          <Badge variant="outline" className={cn('text-xs capitalize', getStatusBadgeClass(mit.status))}>
                            {mit.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-gray-600 text-sm">
                          {mit.linked_threats?.length > 0 ? mit.linked_threats.join(', ') : '-'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </div>
          )}

          {/* CVE Report Table */}
          {report.cves && report.cves.length > 0 && (
            <div>
              <h2 className="text-xl font-bold text-gray-900 mb-4">CVE Report</h2>
              <div className="border rounded-lg overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow className="bg-gray-50">
                      <TableHead className="text-gray-700 font-semibold">CVE ID</TableHead>
                      <TableHead className="text-gray-700 font-semibold text-center">CVSS Score</TableHead>
                      <TableHead className="text-gray-700 font-semibold text-center">Severity</TableHead>
                      <TableHead className="text-gray-700 font-semibold">Description</TableHead>
                      <TableHead className="text-gray-700 font-semibold">Technology</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {report.cves.map((cve) => (
                      <TableRow key={cve.cve_id} className="border-b border-gray-100">
                        <TableCell className="font-mono text-xs text-blue-700 font-medium">{cve.cve_id}</TableCell>
                        <TableCell className="text-center font-bold text-sm">{cve.cvss_score ?? '-'}</TableCell>
                        <TableCell className="text-center">
                          <Badge variant="outline" className={cn('text-xs capitalize', getSeverityBadgeClass(cve.severity))}>
                            {cve.severity ?? 'N/A'}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-gray-600 text-xs max-w-xs truncate">{cve.description}</TableCell>
                        <TableCell className="text-gray-600 text-sm">{cve.technology}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </div>
          )}

          {/* Compliance Mapping */}
          {report.cwes && report.cwes.length > 0 && (
            <div>
              <h2 className="text-xl font-bold text-gray-900 mb-4">Compliance Mapping</h2>
              <div className="border rounded-lg overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow className="bg-gray-50">
                      <TableHead className="text-gray-700 font-semibold">CWE ID</TableHead>
                      <TableHead className="text-gray-700 font-semibold">CWE Name</TableHead>
                      <TableHead className="text-gray-700 font-semibold">Related Threats</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {report.cwes.map((cwe) => (
                      <TableRow key={cwe.cwe_id} className="border-b border-gray-100">
                        <TableCell className="font-mono text-xs text-purple-700 font-medium">{cwe.cwe_id}</TableCell>
                        <TableCell className="font-medium text-gray-900 text-sm">{cwe.name}</TableCell>
                        <TableCell className="text-gray-600 text-sm">
                          {cwe.threats?.length > 0 ? cwe.threats.join(', ') : '-'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </div>
          )}

          {/* Footer */}
          <div className="border-t border-gray-300 pt-4 text-center text-xs text-gray-400">
            Generated by ThreatAtlas Security Platform
          </div>
        </div>
      )}

        </TabsContent>

        {/* Pentest Report Tab */}
        <TabsContent value="pentest" className="space-y-6">
          {/* Pentest Controls */}
          <Card className="border-border/60 rounded-xl shadow-sm">
            <CardContent className="p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                <Select value={selectedPentestProduct} onValueChange={(v) => { setSelectedPentestProduct(v); setSelectedPentest('all'); setPentestReport(null); }}>
                  <SelectTrigger className="w-56 h-10 rounded-lg">
                    <SelectValue placeholder="Select Product" />
                  </SelectTrigger>
                  <SelectContent>
                    {products.map((p) => (
                      <SelectItem key={p.id} value={String(p.id)}>{p.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>

                <Select
                  value={selectedPentest}
                  onValueChange={(v) => { setSelectedPentest(v); setPentestReport(null); }}
                  disabled={!selectedPentestProduct}
                >
                  <SelectTrigger className="w-56 h-10 rounded-lg">
                    <SelectValue placeholder="All Pentests" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Pentests</SelectItem>
                    {pentests.map((pt) => (
                      <SelectItem key={pt.id} value={String(pt.id)}>{pt.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>

                <Button
                  onClick={generatePentestReport}
                  disabled={!selectedPentestProduct || pentestLoading}
                  className="h-10 rounded-lg"
                >
                  {pentestLoading ? (
                    <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Generating...</>
                  ) : (
                    <><FileText className="h-4 w-4 mr-2" /> Generate Report</>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>

          {pentestLoading && (
            <Card className="border-dashed rounded-xl">
              <CardContent className="flex items-center justify-center p-16">
                <div className="flex flex-col items-center gap-3">
                  <div className="h-10 w-10 animate-spin rounded-full border-4 border-primary border-t-transparent" />
                  <p className="text-sm text-muted-foreground font-medium">Generating pentest report...</p>
                </div>
              </CardContent>
            </Card>
          )}

          {!pentestLoading && !pentestReport && (
            <Card className="border-dashed border-2 rounded-xl">
              <CardContent className="flex flex-col items-center justify-center p-16">
                <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-primary/10 to-primary/5 mb-3 shadow-sm">
                  <Crosshair className="h-8 w-8 text-primary" />
                </div>
                <h3 className="text-lg font-bold mb-1.5">No Pentest Report Generated</h3>
                <p className="text-sm text-muted-foreground text-center max-w-sm leading-relaxed">
                  Select a product and click "Generate Report" to create a pentest report.
                </p>
              </CardContent>
            </Card>
          )}

          {pentestReport && !pentestLoading && (
            <div id="pentest-report-content" className="bg-white text-black p-8 space-y-8 rounded-xl border">
              {/* Cover */}
              <div className="border-b-2 border-gray-300 pb-8 mb-8">
                <h1 className="text-3xl font-bold text-gray-900 mb-2">PENTEST REPORT</h1>
                <div className="h-1 w-24 bg-blue-600 mb-6" />
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-gray-500 font-medium">Product:</span>
                    <span className="ml-2 font-semibold text-gray-900">{pentestReport.product_name}</span>
                  </div>
                  <div>
                    <span className="text-gray-500 font-medium">Generated:</span>
                    <span className="ml-2 font-semibold text-gray-900">
                      {new Date(pentestReport.generated_at || new Date()).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500 font-medium">Classification:</span>
                    <span className="ml-2 font-semibold text-red-700">CONFIDENTIAL</span>
                  </div>
                </div>
              </div>

              {/* Executive Summary */}
              {pentestReport.executive_summary && (
                <div>
                  <h2 className="text-xl font-bold text-gray-900 mb-4">Executive Summary</h2>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <Card className="border border-gray-200 shadow-none">
                      <CardContent className="p-4 text-center">
                        <div className="text-2xl font-bold text-gray-900">{pentestReport.executive_summary.total_findings ?? 0}</div>
                        <div className="text-xs text-gray-500 mt-1">Total Findings</div>
                      </CardContent>
                    </Card>
                    <Card className="border border-gray-200 shadow-none">
                      <CardContent className="p-4 text-center">
                        <div className="text-2xl font-bold text-red-600">{pentestReport.executive_summary.critical_findings ?? 0}</div>
                        <div className="text-xs text-gray-500 mt-1">Critical</div>
                      </CardContent>
                    </Card>
                    <Card className="border border-gray-200 shadow-none">
                      <CardContent className="p-4 text-center">
                        <div className="text-2xl font-bold text-gray-900">{Math.round(pentestReport.executive_summary.health_score ?? 0)}%</div>
                        <div className="text-xs text-gray-500 mt-1">Health Score</div>
                      </CardContent>
                    </Card>
                    <Card className="border border-gray-200 shadow-none">
                      <CardContent className="p-4 text-center">
                        <div className="text-2xl font-bold text-gray-900">{pentestReport.executive_summary.total_pentests ?? 0}</div>
                        <div className="text-xs text-gray-500 mt-1">Pentests</div>
                      </CardContent>
                    </Card>
                  </div>
                </div>
              )}

              {/* Per-Pentest Sections */}
              {pentestReport.pentests && pentestReport.pentests.map((pt: any) => {
                const ptFindings = pt.findings || [];
                // Risk Matrix data
                const sevMap: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
                const heatmapFindings = ptFindings.filter((f: any) => f.likelihood != null && f.severity);
                const countMap: Record<string, number> = {};
                heatmapFindings.forEach((f: any) => {
                  const key = `${f.likelihood}-${sevMap[f.severity] || 1}`;
                  countMap[key] = (countMap[key] || 0) + 1;
                });
                const heatmapRows = [5, 4, 3, 2, 1];
                const heatmapCols = [1, 2, 3, 4];
                const colLabels = ['Low', 'Medium', 'High', 'Critical'];
                const getCellColor = (likelihood: number, impact: number) => {
                  const score = likelihood * impact;
                  if (score >= 16) return 'bg-red-500 text-white';
                  if (score >= 12) return 'bg-red-400 text-white';
                  if (score >= 8) return 'bg-orange-400 text-white';
                  if (score >= 6) return 'bg-orange-300 text-orange-900';
                  if (score >= 4) return 'bg-yellow-300 text-yellow-900';
                  if (score >= 2) return 'bg-yellow-200 text-yellow-800';
                  return 'bg-green-200 text-green-800';
                };
                const getPriorityBadgeClass = (priority: string) => {
                  switch (priority) {
                    case 'immediate': return 'bg-red-100 text-red-800 border-red-200';
                    case 'short_term': return 'bg-orange-100 text-orange-800 border-orange-200';
                    case 'long_term': return 'bg-blue-100 text-blue-800 border-blue-200';
                    case 'accepted': return 'bg-gray-100 text-gray-600 border-gray-200';
                    default: return '';
                  }
                };
                const getRiskBadgeClass = (score: number) => {
                  if (score >= 20) return 'bg-red-100 text-red-800 border-red-200';
                  if (score >= 12) return 'bg-orange-100 text-orange-800 border-orange-200';
                  if (score >= 6) return 'bg-yellow-100 text-yellow-800 border-yellow-200';
                  return 'bg-green-100 text-green-800 border-green-200';
                };

                return (
                  <div key={pt.id || pt.name}>
                    <h2 className="text-xl font-bold text-gray-900 mb-2">{pt.name}</h2>

                    {/* Testing Timeline */}
                    <div className="bg-gray-50 rounded-lg p-4 mb-4">
                      <h3 className="text-sm font-semibold text-gray-700 mb-3">Testing Timeline</h3>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                        {pt.vendor_name && (
                          <div>
                            <span className="text-gray-500">Vendor:</span>
                            <span className="ml-1 font-medium text-gray-900">{pt.vendor_name}</span>
                          </div>
                        )}
                        {pt.tester_name && (
                          <div>
                            <span className="text-gray-500">Tester:</span>
                            <span className="ml-1 font-medium text-gray-900">{pt.tester_name}</span>
                          </div>
                        )}
                        {pt.started_at && (
                          <div>
                            <span className="text-gray-500">Start:</span>
                            <span className="ml-1 font-medium text-gray-900">{new Date(pt.started_at).toLocaleDateString()}</span>
                          </div>
                        )}
                        {pt.completed_at && (
                          <div>
                            <span className="text-gray-500">End:</span>
                            <span className="ml-1 font-medium text-gray-900">{new Date(pt.completed_at).toLocaleDateString()}</span>
                          </div>
                        )}
                        {pt.started_at && pt.completed_at && (
                          <div>
                            <span className="text-gray-500">Duration:</span>
                            <span className="ml-1 font-medium text-gray-900">
                              {Math.ceil((new Date(pt.completed_at).getTime() - new Date(pt.started_at).getTime()) / (1000 * 60 * 60 * 24))} days
                            </span>
                          </div>
                        )}
                        <div>
                          <span className="text-gray-500">Status:</span>
                          <Badge variant="outline" className={cn('ml-1 text-xs capitalize', getStatusBadgeClass(pt.status))}>{pt.status?.replace('_', ' ')}</Badge>
                        </div>
                      </div>
                    </div>

                    {/* Scope & Methodology */}
                    {(pt.scope || pt.scope_exclusions || pt.methodology || pt.tools_used) && (
                      <div className="bg-gray-50 rounded-lg p-4 mb-4">
                        <h3 className="text-sm font-semibold text-gray-700 mb-3">Scope & Methodology</h3>
                        <div className="space-y-2 text-sm">
                          {pt.methodology && (
                            <div>
                              <span className="text-gray-500 font-medium">Methodology:</span>
                              <span className="ml-1 text-gray-900">{pt.methodology}</span>
                            </div>
                          )}
                          {pt.scope && (
                            <div>
                              <span className="text-gray-500 font-medium">Scope:</span>
                              <p className="text-gray-900 mt-0.5 whitespace-pre-wrap">{pt.scope}</p>
                            </div>
                          )}
                          {pt.scope_exclusions && (
                            <div>
                              <span className="text-gray-500 font-medium">Out of Scope:</span>
                              <p className="text-gray-900 mt-0.5 whitespace-pre-wrap">{pt.scope_exclusions}</p>
                            </div>
                          )}
                          {pt.tools_used && (
                            <div>
                              <span className="text-gray-500 font-medium">Tools Used:</span>
                              <p className="text-gray-900 mt-0.5 whitespace-pre-wrap">{pt.tools_used}</p>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Risk Matrix */}
                    {heatmapFindings.length > 0 && (
                      <div className="mb-4">
                        <h3 className="text-sm font-semibold text-gray-700 mb-3">Risk Matrix</h3>
                        <div className="flex items-end gap-1 max-w-md">
                          <div className="w-16 flex flex-col items-center justify-center">
                            <span className="text-xs font-semibold text-gray-500" style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)' }}>Likelihood</span>
                          </div>
                          <div className="flex-1">
                            <div className="space-y-1">
                              {heatmapRows.map((likelihood) => (
                                <div key={likelihood} className="flex items-center gap-1">
                                  <div className="w-6 text-center text-xs font-medium text-gray-500">{likelihood}</div>
                                  {heatmapCols.map((impact) => {
                                    const count = countMap[`${likelihood}-${impact}`] || 0;
                                    return (
                                      <div key={`${likelihood}-${impact}`}
                                        className={`flex-1 h-10 flex items-center justify-center rounded text-xs font-bold ${getCellColor(likelihood, impact)} ${count > 0 ? 'ring-1 ring-gray-400 shadow' : ''}`}
                                      >
                                        {count > 0 ? count : ''}
                                      </div>
                                    );
                                  })}
                                </div>
                              ))}
                              <div className="flex items-center gap-1">
                                <div className="w-6" />
                                {colLabels.map((label) => (
                                  <div key={label} className="flex-1 text-center text-xs font-medium text-gray-500">{label}</div>
                                ))}
                              </div>
                            </div>
                            <div className="text-center mt-1"><span className="text-xs font-semibold text-gray-500">Severity</span></div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Findings Table */}
                    {ptFindings.length > 0 ? (
                      <div className="border rounded-lg overflow-hidden mb-6">
                        <Table>
                          <TableHeader>
                            <TableRow className="bg-gray-50">
                              <TableHead className="text-gray-700 font-semibold w-10">#</TableHead>
                              <TableHead className="text-gray-700 font-semibold">Title</TableHead>
                              <TableHead className="text-gray-700 font-semibold text-center">Severity</TableHead>
                              <TableHead className="text-gray-700 font-semibold text-center">Likelihood</TableHead>
                              <TableHead className="text-gray-700 font-semibold text-center">CVSS</TableHead>
                              <TableHead className="text-gray-700 font-semibold text-center">Risk</TableHead>
                              <TableHead className="text-gray-700 font-semibold">Category</TableHead>
                              <TableHead className="text-gray-700 font-semibold text-center">Status</TableHead>
                              <TableHead className="text-gray-700 font-semibold text-center">Priority</TableHead>
                              <TableHead className="text-gray-700 font-semibold">Due Date</TableHead>
                              <TableHead className="text-gray-700 font-semibold">Assigned To</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {ptFindings.map((f: any, idx: number) => (
                              <TableRow key={f.id || idx} className="border-b border-gray-100">
                                <TableCell className="text-gray-500 text-xs">{idx + 1}</TableCell>
                                <TableCell className="font-medium text-gray-900 text-sm">{f.title}</TableCell>
                                <TableCell className="text-center">
                                  <Badge variant="outline" className={cn('text-xs capitalize', getSeverityBadgeClass(f.severity))}>
                                    {f.severity ?? 'N/A'}
                                  </Badge>
                                </TableCell>
                                <TableCell className="text-center text-sm text-gray-600">{f.likelihood ?? '-'}</TableCell>
                                <TableCell className="text-center text-sm text-gray-600">{f.cvss_score != null ? Number(f.cvss_score).toFixed(1) : '-'}</TableCell>
                                <TableCell className="text-center">
                                  {f.risk_score != null ? (
                                    <Badge variant="outline" className={cn('text-xs border', getRiskBadgeClass(f.risk_score))}>
                                      {f.risk_score}
                                    </Badge>
                                  ) : '-'}
                                </TableCell>
                                <TableCell className="text-gray-600 text-sm">{f.category || '-'}</TableCell>
                                <TableCell className="text-center">
                                  <Badge variant="outline" className={cn('text-xs capitalize', getStatusBadgeClass(f.status))}>
                                    {f.status?.replace('_', ' ')}
                                  </Badge>
                                </TableCell>
                                <TableCell className="text-center">
                                  {f.remediation_priority ? (
                                    <Badge variant="outline" className={cn('text-xs capitalize', getPriorityBadgeClass(f.remediation_priority))}>
                                      {f.remediation_priority.replace('_', ' ')}
                                    </Badge>
                                  ) : '-'}
                                </TableCell>
                                <TableCell className="text-gray-600 text-sm">{f.due_date ? new Date(f.due_date).toLocaleDateString() : '-'}</TableCell>
                                <TableCell className="text-gray-600 text-sm">{f.assigned_to || '-'}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                    ) : (
                      <p className="text-sm text-gray-500 mb-6">No findings for this pentest.</p>
                    )}
                  </div>
                );
              })}

              {/* Footer */}
              <div className="border-t border-gray-300 pt-4 text-center text-xs text-gray-400">
                Generated by ThreatAtlas Security Platform
              </div>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
