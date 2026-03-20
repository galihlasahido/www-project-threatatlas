import { useState, useEffect, useRef } from 'react';
import { pentestFindingsApi, cwesApi, cvesApi, diagramThreatsApi } from '@/lib/api';

const FINDING_CATEGORIES = [
  'Injection', 'Broken Authentication', 'Sensitive Data Exposure',
  'XML External Entity (XXE)', 'Broken Access Control', 'Security Misconfiguration',
  'Cross-Site Scripting (XSS)', 'Insecure Deserialization',
  'Using Components with Known Vulnerabilities', 'Insufficient Logging & Monitoring',
  'Server-Side Request Forgery (SSRF)', 'Cryptographic Failures',
  'Business Logic', 'Denial of Service', 'Information Disclosure',
  'Privilege Escalation', 'File Upload', 'Remote Code Execution', 'Other',
];
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Loader2, Save, X, Search, Link2, ShieldAlert } from 'lucide-react';
import { cn } from '@/lib/utils';
import { getSeverityClasses } from '@/lib/risk';
import EvidenceSection from './EvidenceSection';
import RetestTimeline from './RetestTimeline';

interface FindingDetailSheetProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  findingId: number | null;
  onRefresh: () => void;
}

export default function FindingDetailSheet({ open, onOpenChange, findingId, onRefresh }: FindingDetailSheetProps) {
  const [finding, setFinding] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [evidence, setEvidence] = useState<any[]>([]);
  const [retests, setRetests] = useState<any[]>([]);
  const [linkedCWEs, setLinkedCWEs] = useState<any[]>([]);
  const [linkedCVEs, setLinkedCVEs] = useState<any[]>([]);
  const [linkedThreats, setLinkedThreats] = useState<any[]>([]);

  // Link dialogs
  const [cweDialogOpen, setCweDialogOpen] = useState(false);
  const [cveDialogOpen, setCveDialogOpen] = useState(false);
  const [threatDialogOpen, setThreatDialogOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [searching, setSearching] = useState(false);

  // Editable fields
  const [editData, setEditData] = useState({
    title: '',
    severity: '',
    status: '',
    description: '',
    steps_to_reproduce: '',
    recommendation: '',
    affected_element: '',
    category: '',
    patched_at: '',
    likelihood: '',
    cvss_score: '',
    cvss_vector: '',
    remediation_priority: '',
    due_date: '',
    assigned_to: '',
  });

  useEffect(() => {
    if (open && findingId) {
      loadFinding();
    }
  }, [open, findingId]);

  const loadFinding = async () => {
    if (!findingId) return;
    setLoading(true);
    try {
      const [findingRes, retestsRes] = await Promise.all([
        pentestFindingsApi.get(findingId),
        pentestFindingsApi.listRetests(findingId),
      ]);
      const data = findingRes.data;
      setFinding(data);
      setEditData({
        title: data.title || '',
        severity: data.severity || 'medium',
        status: data.status || 'open',
        description: data.description || '',
        steps_to_reproduce: data.steps_to_reproduce || '',
        recommendation: data.recommendation || '',
        affected_element: data.affected_element || '',
        category: data.category || '',
        patched_at: data.patched_at ? data.patched_at.split('T')[0] : '',
        likelihood: data.likelihood ? String(data.likelihood) : '',
        cvss_score: data.cvss_score != null ? String(data.cvss_score) : '',
        cvss_vector: data.cvss_vector || '',
        remediation_priority: data.remediation_priority || '',
        due_date: data.due_date ? data.due_date.split('T')[0] : '',
        assigned_to: data.assigned_to || '',
      });
      setEvidence(data.evidence || []);
      setLinkedCWEs(data.cwes || []);
      setLinkedCVEs(data.cves || []);
      setLinkedThreats(data.diagram_threats || []);
      setRetests(retestsRes.data || []);
    } catch (error) {
      console.error('Error loading finding:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    if (!findingId) return;
    setSaving(true);
    try {
      const payload: any = { ...editData };
      if (payload.patched_at) {
        payload.patched_at = new Date(payload.patched_at).toISOString();
      } else {
        payload.patched_at = null;
      }
      if (payload.likelihood) payload.likelihood = Number(payload.likelihood);
      else payload.likelihood = null;
      if (payload.cvss_score !== '') payload.cvss_score = Number(payload.cvss_score);
      else payload.cvss_score = null;
      if (!payload.cvss_vector) payload.cvss_vector = null;
      if (!payload.remediation_priority) payload.remediation_priority = null;
      if (payload.due_date) payload.due_date = new Date(payload.due_date).toISOString();
      else payload.due_date = null;
      if (!payload.assigned_to) payload.assigned_to = null;
      await pentestFindingsApi.update(findingId, payload);
      onRefresh();
      loadFinding();
    } catch (error) {
      console.error('Error saving finding:', error);
    } finally {
      setSaving(false);
    }
  };

  // CWE linking
  const searchCWEs = async (query: string) => {
    if (!query.trim()) return;
    setSearching(true);
    try {
      const res = await cwesApi.list({ search: query });
      setSearchResults(res.data?.slice(0, 20) || []);
    } catch (error) {
      console.error('Error searching CWEs:', error);
    } finally {
      setSearching(false);
    }
  };

  const handleLinkCWE = async (cweId: number) => {
    if (!findingId) return;
    try {
      await pentestFindingsApi.linkCWE(findingId, cweId);
      setCweDialogOpen(false);
      setSearchQuery('');
      setSearchResults([]);
      loadFinding();
    } catch (error) {
      console.error('Error linking CWE:', error);
    }
  };

  const handleUnlinkCWE = async (cweId: number) => {
    if (!findingId) return;
    try {
      await pentestFindingsApi.unlinkCWE(findingId, cweId);
      loadFinding();
    } catch (error) {
      console.error('Error unlinking CWE:', error);
    }
  };

  // CVE linking
  const searchCVEs = async (query: string) => {
    if (!query.trim()) return;
    setSearching(true);
    try {
      const res = await cvesApi.list({ keyword: query, limit: 20 });
      setSearchResults(res.data || []);
    } catch (error) {
      console.error('Error searching CVEs:', error);
    } finally {
      setSearching(false);
    }
  };

  const handleLinkCVE = async (cveId: number) => {
    if (!findingId) return;
    try {
      await pentestFindingsApi.linkCVE(findingId, cveId);
      setCveDialogOpen(false);
      setSearchQuery('');
      setSearchResults([]);
      loadFinding();
    } catch (error) {
      console.error('Error linking CVE:', error);
    }
  };

  const handleUnlinkCVE = async (cveId: number) => {
    if (!findingId) return;
    try {
      await pentestFindingsApi.unlinkCVE(findingId, cveId);
      loadFinding();
    } catch (error) {
      console.error('Error unlinking CVE:', error);
    }
  };

  // Threat linking
  const searchThreats = async (query: string) => {
    if (!query.trim()) return;
    setSearching(true);
    try {
      const res = await diagramThreatsApi.list();
      const filtered = (res.data || []).filter((t: any) =>
        t.threat?.name?.toLowerCase().includes(query.toLowerCase()) ||
        t.element_id?.toLowerCase().includes(query.toLowerCase())
      );
      setSearchResults(filtered.slice(0, 20));
    } catch (error) {
      console.error('Error searching threats:', error);
    } finally {
      setSearching(false);
    }
  };

  const handleLinkThreat = async (dtId: number) => {
    if (!findingId) return;
    try {
      await pentestFindingsApi.linkThreat(findingId, dtId);
      setThreatDialogOpen(false);
      setSearchQuery('');
      setSearchResults([]);
      loadFinding();
    } catch (error) {
      console.error('Error linking threat:', error);
    }
  };

  const handleUnlinkThreat = async (dtId: number) => {
    if (!findingId) return;
    try {
      await pentestFindingsApi.unlinkThreat(findingId, dtId);
      loadFinding();
    } catch (error) {
      console.error('Error unlinking threat:', error);
    }
  };

  const showPatchDate = ['patched', 'verified', 'closed'].includes(editData.status);

  const getRiskScoreBadge = (score: number | null | undefined) => {
    if (score == null) return { label: 'N/A', className: 'bg-gray-100 text-gray-600 border-gray-200' };
    if (score >= 20) return { label: `${score} Critical`, className: 'bg-red-100 text-red-800 border-red-200' };
    if (score >= 12) return { label: `${score} High`, className: 'bg-orange-100 text-orange-800 border-orange-200' };
    if (score >= 6) return { label: `${score} Medium`, className: 'bg-yellow-100 text-yellow-800 border-yellow-200' };
    return { label: `${score} Low`, className: 'bg-green-100 text-green-800 border-green-200' };
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

  const riskBadge = getRiskScoreBadge(finding?.risk_score);

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-green-100 text-green-800 border-green-200';
      default: return '';
    }
  };

  return (
    <>
      <Sheet open={open} onOpenChange={onOpenChange}>
        <SheetContent className="w-[600px] sm:max-w-[600px] p-0">
          {loading ? (
            <div className="flex items-center justify-center h-full">
              <div className="flex flex-col items-center gap-3">
                <div className="h-10 w-10 animate-spin rounded-full border-4 border-primary border-t-transparent" />
                <p className="text-sm text-muted-foreground">Loading finding...</p>
              </div>
            </div>
          ) : finding ? (
            <div className="flex flex-col h-full">
              <SheetHeader className="px-6 py-4 border-b">
                <div className="flex items-center gap-3">
                  <Badge variant="outline" className={cn('capitalize border', getSeverityBadgeClass(editData.severity))}>
                    {editData.severity}
                  </Badge>
                  <SheetTitle className="flex-1">
                    <Input
                      value={editData.title}
                      onChange={(e) => setEditData({ ...editData, title: e.target.value })}
                      className="text-lg font-bold border-none p-0 h-auto focus-visible:ring-0 shadow-none"
                    />
                  </SheetTitle>
                </div>
                <div className="flex items-center gap-2 mt-2 flex-wrap">
                  <Select value={editData.severity} onValueChange={(v) => setEditData({ ...editData, severity: v })}>
                    <SelectTrigger className="h-8 w-28 text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                  <Select value={editData.status} onValueChange={(v) => setEditData({ ...editData, status: v })}>
                    <SelectTrigger className="h-8 w-28 text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="open">Open</SelectItem>
                      <SelectItem value="in_progress">In Progress</SelectItem>
                      <SelectItem value="patched">Patched</SelectItem>
                      <SelectItem value="verified">Verified</SelectItem>
                      <SelectItem value="closed">Closed</SelectItem>
                      <SelectItem value="accepted">Accepted</SelectItem>
                      <SelectItem value="false_positive">False Positive</SelectItem>
                    </SelectContent>
                  </Select>
                  <Select value={editData.likelihood} onValueChange={(v) => setEditData({ ...editData, likelihood: v })}>
                    <SelectTrigger className="h-8 w-28 text-xs">
                      <SelectValue placeholder="Likelihood" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1">1 - Rare</SelectItem>
                      <SelectItem value="2">2 - Unlikely</SelectItem>
                      <SelectItem value="3">3 - Possible</SelectItem>
                      <SelectItem value="4">4 - Likely</SelectItem>
                      <SelectItem value="5">5 - Certain</SelectItem>
                    </SelectContent>
                  </Select>
                  {finding?.risk_score != null && (
                    <Badge variant="outline" className={cn('text-xs border', riskBadge.className)}>
                      Risk: {riskBadge.label}
                    </Badge>
                  )}
                  <Button size="sm" onClick={handleSave} disabled={saving} className="h-8 ml-auto">
                    {saving ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Save className="h-3.5 w-3.5 mr-1.5" />}
                    Save
                  </Button>
                </div>
              </SheetHeader>

              <ScrollArea className="flex-1 px-6 py-4">
                <div className="space-y-6">
                  {/* Description */}
                  <div className="space-y-2">
                    <Label className="text-xs font-bold text-muted-foreground tracking-wider">DESCRIPTION</Label>
                    <Textarea
                      value={editData.description}
                      onChange={(e) => setEditData({ ...editData, description: e.target.value })}
                      placeholder="Describe the finding..."
                      className="min-h-[80px] text-sm"
                    />
                  </div>

                  {/* Steps to Reproduce */}
                  <div className="space-y-2">
                    <Label className="text-xs font-bold text-muted-foreground tracking-wider">STEPS TO REPRODUCE</Label>
                    <Textarea
                      value={editData.steps_to_reproduce}
                      onChange={(e) => setEditData({ ...editData, steps_to_reproduce: e.target.value })}
                      placeholder="Steps to reproduce..."
                      className="min-h-[80px] text-sm"
                    />
                  </div>

                  {/* Recommendation */}
                  <div className="space-y-2">
                    <Label className="text-xs font-bold text-muted-foreground tracking-wider">RECOMMENDATION</Label>
                    <Textarea
                      value={editData.recommendation}
                      onChange={(e) => setEditData({ ...editData, recommendation: e.target.value })}
                      placeholder="Recommended remediation..."
                      className="min-h-[60px] text-sm"
                    />
                  </div>

                  {/* Affected Element & Category */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label className="text-xs font-bold text-muted-foreground tracking-wider">AFFECTED ELEMENT</Label>
                      <Input
                        value={editData.affected_element}
                        onChange={(e) => setEditData({ ...editData, affected_element: e.target.value })}
                        placeholder="e.g. /api/users"
                        className="text-sm"
                      />
                    </div>
                    <div className="space-y-2 relative">
                      <Label className="text-xs font-bold text-muted-foreground tracking-wider">CATEGORY</Label>
                      <Input
                        value={editData.category}
                        onChange={(e) => setEditData({ ...editData, category: e.target.value })}
                        onFocus={(e) => (e.target as any).nextSibling?.classList.remove('hidden')}
                        onBlur={() => setTimeout(() => document.querySelector('.cat-dropdown')?.classList.add('hidden'), 200)}
                        placeholder="Select or type category..."
                        className="text-sm"
                        autoComplete="off"
                      />
                      <div className="cat-dropdown hidden absolute z-50 top-full left-0 right-0 mt-1 bg-popover border rounded-lg shadow-lg max-h-40 overflow-auto">
                        {FINDING_CATEGORIES.filter(c => c.toLowerCase().includes((editData.category || '').toLowerCase())).map(cat => (
                          <button
                            key={cat}
                            type="button"
                            className="w-full text-left px-3 py-1.5 text-xs hover:bg-muted transition-colors"
                            onMouseDown={(e) => { e.preventDefault(); setEditData({ ...editData, category: cat }); document.querySelector('.cat-dropdown')?.classList.add('hidden'); }}
                          >
                            {cat}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* CVSS & Risk Details */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label className="text-xs font-bold text-muted-foreground tracking-wider">CVSS SCORE</Label>
                      <Input
                        type="number"
                        min="0"
                        max="10"
                        step="0.1"
                        value={editData.cvss_score}
                        onChange={(e) => setEditData({ ...editData, cvss_score: e.target.value })}
                        placeholder="0.0 - 10.0"
                        className="text-sm"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label className="text-xs font-bold text-muted-foreground tracking-wider">REMEDIATION PRIORITY</Label>
                      <Select value={editData.remediation_priority} onValueChange={(v) => setEditData({ ...editData, remediation_priority: v })}>
                        <SelectTrigger className="text-sm">
                          <SelectValue placeholder="Select priority..." />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="immediate">Immediate</SelectItem>
                          <SelectItem value="short_term">Short-term</SelectItem>
                          <SelectItem value="long_term">Long-term</SelectItem>
                          <SelectItem value="accepted">Accepted</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label className="text-xs font-bold text-muted-foreground tracking-wider">CVSS VECTOR</Label>
                    <Input
                      value={editData.cvss_vector}
                      onChange={(e) => setEditData({ ...editData, cvss_vector: e.target.value })}
                      placeholder="e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                      className="text-sm font-mono text-xs"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label className="text-xs font-bold text-muted-foreground tracking-wider">DUE DATE</Label>
                      <Input
                        type="date"
                        value={editData.due_date}
                        onChange={(e) => setEditData({ ...editData, due_date: e.target.value })}
                        className="text-sm w-full"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label className="text-xs font-bold text-muted-foreground tracking-wider">ASSIGNED TO</Label>
                      <Input
                        value={editData.assigned_to}
                        onChange={(e) => setEditData({ ...editData, assigned_to: e.target.value })}
                        placeholder="Who will fix this?"
                        className="text-sm"
                      />
                    </div>
                  </div>

                  {/* Risk Score (read-only) */}
                  {finding?.risk_score != null && (
                    <div className="space-y-2">
                      <Label className="text-xs font-bold text-muted-foreground tracking-wider">RISK SCORE (AUTO-COMPUTED)</Label>
                      <div>
                        <Badge variant="outline" className={cn('text-sm px-3 py-1 border', riskBadge.className)}>
                          {riskBadge.label}
                        </Badge>
                      </div>
                    </div>
                  )}

                  {/* Patch Date */}
                  {showPatchDate && (
                    <div className="space-y-2">
                      <Label className="text-xs font-bold text-muted-foreground tracking-wider">PATCH DATE</Label>
                      <Input
                        type="date"
                        value={editData.patched_at}
                        onChange={(e) => setEditData({ ...editData, patched_at: e.target.value })}
                        className="text-sm w-48"
                      />
                    </div>
                  )}

                  <Separator />

                  {/* Evidence */}
                  <div className="space-y-2">
                    <Label className="text-xs font-bold text-muted-foreground tracking-wider">EVIDENCE</Label>
                    <EvidenceSection findingId={findingId!} evidence={evidence} onRefresh={loadFinding} />
                  </div>

                  <Separator />

                  {/* Linked CWEs */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label className="text-xs font-bold text-muted-foreground tracking-wider">LINKED CWES</Label>
                      <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => { setCweDialogOpen(true); setSearchResults([]); setSearchQuery(''); }}>
                        <Link2 className="h-3 w-3 mr-1" /> Link CWE
                      </Button>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {linkedCWEs.length === 0 ? (
                        <p className="text-xs text-muted-foreground italic">No CWEs linked.</p>
                      ) : linkedCWEs.map((cwe: any) => (
                        <Badge key={cwe.id} variant="outline" className="text-xs gap-1 pr-1">
                          CWE-{cwe.cwe_id || cwe.id}: {cwe.name}
                          <button onClick={() => handleUnlinkCWE(cwe.id)} className="ml-1 hover:text-destructive">
                            <X className="h-3 w-3" />
                          </button>
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {/* Linked CVEs */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label className="text-xs font-bold text-muted-foreground tracking-wider">LINKED CVES</Label>
                      <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => { setCveDialogOpen(true); setSearchResults([]); setSearchQuery(''); }}>
                        <Link2 className="h-3 w-3 mr-1" /> Link CVE
                      </Button>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {linkedCVEs.length === 0 ? (
                        <p className="text-xs text-muted-foreground italic">No CVEs linked.</p>
                      ) : linkedCVEs.map((cve: any) => (
                        <Badge key={cve.id} variant="outline" className="text-xs gap-1 pr-1 font-mono">
                          {cve.cve_id}
                          <button onClick={() => handleUnlinkCVE(cve.id)} className="ml-1 hover:text-destructive">
                            <X className="h-3 w-3" />
                          </button>
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {/* Linked Threats */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label className="text-xs font-bold text-muted-foreground tracking-wider">LINKED THREATS</Label>
                      <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => { setThreatDialogOpen(true); setSearchResults([]); setSearchQuery(''); }}>
                        <ShieldAlert className="h-3 w-3 mr-1" /> Link Threat
                      </Button>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {linkedThreats.length === 0 ? (
                        <p className="text-xs text-muted-foreground italic">No threats linked.</p>
                      ) : linkedThreats.map((dt: any) => (
                        <Badge key={dt.id} variant="outline" className={cn("text-xs gap-1 pr-1 capitalize", getSeverityClasses(dt.severity))}>
                          {dt.threat?.name || `Threat #${dt.id}`}
                          <button onClick={() => handleUnlinkThreat(dt.id)} className="ml-1 hover:text-destructive">
                            <X className="h-3 w-3" />
                          </button>
                        </Badge>
                      ))}
                    </div>
                  </div>

                  <Separator />

                  {/* Retest History */}
                  <div className="space-y-2">
                    <Label className="text-xs font-bold text-muted-foreground tracking-wider">RETEST HISTORY</Label>
                    <RetestTimeline findingId={findingId!} retests={retests} onRefresh={loadFinding} />
                  </div>
                </div>
              </ScrollArea>
            </div>
          ) : (
            <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
              Finding not found.
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* CWE Link Dialog */}
      <Dialog open={cweDialogOpen} onOpenChange={setCweDialogOpen}>
        <DialogContent className="sm:max-w-[480px]">
          <DialogHeader>
            <DialogTitle>Link CWE</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search CWEs..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && searchCWEs(searchQuery)}
                  className="pl-9"
                />
              </div>
              <Button onClick={() => searchCWEs(searchQuery)} disabled={searching}>
                {searching ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Search'}
              </Button>
            </div>
            <div className="max-h-[300px] overflow-y-auto space-y-1">
              {searchResults.map((cwe: any) => (
                <div
                  key={cwe.id}
                  className="flex items-center justify-between p-2 rounded-lg hover:bg-muted cursor-pointer"
                  onClick={() => handleLinkCWE(cwe.id)}
                >
                  <div>
                    <span className="text-sm font-medium">CWE-{cwe.cwe_id || cwe.id}</span>
                    <span className="text-sm text-muted-foreground ml-2">{cwe.name}</span>
                  </div>
                  <Link2 className="h-4 w-4 text-muted-foreground" />
                </div>
              ))}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCweDialogOpen(false)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* CVE Link Dialog */}
      <Dialog open={cveDialogOpen} onOpenChange={setCveDialogOpen}>
        <DialogContent className="sm:max-w-[480px]">
          <DialogHeader>
            <DialogTitle>Link CVE</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search CVEs..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && searchCVEs(searchQuery)}
                  className="pl-9"
                />
              </div>
              <Button onClick={() => searchCVEs(searchQuery)} disabled={searching}>
                {searching ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Search'}
              </Button>
            </div>
            <div className="max-h-[300px] overflow-y-auto space-y-1">
              {searchResults.map((cve: any) => (
                <div
                  key={cve.id}
                  className="flex items-center justify-between p-2 rounded-lg hover:bg-muted cursor-pointer"
                  onClick={() => handleLinkCVE(cve.id)}
                >
                  <div>
                    <span className="text-sm font-mono font-medium">{cve.cve_id}</span>
                    <p className="text-xs text-muted-foreground truncate max-w-[350px]">{cve.description}</p>
                  </div>
                  <Link2 className="h-4 w-4 text-muted-foreground shrink-0" />
                </div>
              ))}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCveDialogOpen(false)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Threat Link Dialog */}
      <Dialog open={threatDialogOpen} onOpenChange={setThreatDialogOpen}>
        <DialogContent className="sm:max-w-[480px]">
          <DialogHeader>
            <DialogTitle>Link Diagram Threat</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search threats..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && searchThreats(searchQuery)}
                  className="pl-9"
                />
              </div>
              <Button onClick={() => searchThreats(searchQuery)} disabled={searching}>
                {searching ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Search'}
              </Button>
            </div>
            <div className="max-h-[300px] overflow-y-auto space-y-1">
              {searchResults.map((dt: any) => (
                <div
                  key={dt.id}
                  className="flex items-center justify-between p-2 rounded-lg hover:bg-muted cursor-pointer"
                  onClick={() => handleLinkThreat(dt.id)}
                >
                  <div>
                    <span className="text-sm font-medium">{dt.threat?.name || `Threat #${dt.id}`}</span>
                    <p className="text-xs text-muted-foreground">Element: {dt.element_id} | {dt.severity || 'N/A'}</p>
                  </div>
                  <Link2 className="h-4 w-4 text-muted-foreground shrink-0" />
                </div>
              ))}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setThreatDialogOpen(false)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
