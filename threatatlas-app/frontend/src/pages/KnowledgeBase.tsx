import { useState, useEffect } from 'react';
import { frameworksApi, threatsApi, mitigationsApi, cwesApi } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '@/components/ui/sheet';
import { Library, AlertTriangle, Shield, Sparkles, Plus, MoreVertical, Pencil, Trash2, Search, X, Eye, FileText, ExternalLink, Bug } from 'lucide-react';

interface Framework {
  id: number;
  name: string;
  description: string;
}

interface Threat {
  id: number;
  framework_id: number;
  name: string;
  description: string;
  category: string;
  is_custom: boolean;
}

interface Mitigation {
  id: number;
  framework_id: number;
  name: string;
  description: string;
  category: string;
  is_custom: boolean;
}

interface CWE {
  id: number;
  cwe_id: string;
  name: string;
  description: string | null;
  category: string | null;
  severity: string | null;
  url: string | null;
  created_at: string;
  updated_at: string;
}

export default function KnowledgeBase() {
  const { canWrite } = useAuth();
  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [selectedFramework, setSelectedFramework] = useState<number | null>(null);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [mitigations, setMitigations] = useState<Mitigation[]>([]);
  const [loading, setLoading] = useState(true);

  // Filter state
  const [threatSearch, setThreatSearch] = useState('');
  const [threatCategoryFilter, setThreatCategoryFilter] = useState('all');
  const [mitigationSearch, setMitigationSearch] = useState('');
  const [mitigationCategoryFilter, setMitigationCategoryFilter] = useState('all');

  // Threat dialog state
  const [threatDialogOpen, setThreatDialogOpen] = useState(false);
  const [editingThreat, setEditingThreat] = useState<Threat | null>(null);
  const [threatForm, setThreatForm] = useState({ name: '', description: '', category: '' });
  const [deleteThreatOpen, setDeleteThreatOpen] = useState(false);
  const [threatToDelete, setThreatToDelete] = useState<Threat | null>(null);

  // Mitigation dialog state
  const [mitigationDialogOpen, setMitigationDialogOpen] = useState(false);
  const [editingMitigation, setEditingMitigation] = useState<Mitigation | null>(null);
  const [mitigationForm, setMitigationForm] = useState({ name: '', description: '', category: '' });
  const [deleteMitigationOpen, setDeleteMitigationOpen] = useState(false);
  const [mitigationToDelete, setMitigationToDelete] = useState<Mitigation | null>(null);

  // Threat detail sheet state
  const [threatDetailOpen, setThreatDetailOpen] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [threatCWEs, setThreatCWEs] = useState<CWE[]>([]);
  const [editDescription, setEditDescription] = useState('');
  const [savingDescription, setSavingDescription] = useState(false);
  const [loadingThreatCWEs, setLoadingThreatCWEs] = useState(false);

  // Mitigation detail sheet state
  const [mitigationDetailOpen, setMitigationDetailOpen] = useState(false);
  const [selectedMitigation, setSelectedMitigation] = useState<Mitigation | null>(null);
  const [editMitigationDescription, setEditMitigationDescription] = useState('');
  const [savingMitigationDescription, setSavingMitigationDescription] = useState(false);

  // CWE tab state
  const [cwes, setCWEs] = useState<CWE[]>([]);
  const [cweSearch, setCweSearch] = useState('');
  const [selectedCWE, setSelectedCWE] = useState<CWE | null>(null);
  const [cweDetailOpen, setCweDetailOpen] = useState(false);
  const [cweThreatLinks, setCweThreatLinks] = useState<Threat[]>([]);
  const [loadingCWEs, setLoadingCWEs] = useState(false);
  const [loadingCweThreats, setLoadingCweThreats] = useState(false);

  useEffect(() => {
    loadFrameworks();
    loadCWEs();
  }, []);

  useEffect(() => {
    if (selectedFramework) {
      loadThreats(selectedFramework);
      loadMitigations(selectedFramework);
      setThreatSearch('');
      setThreatCategoryFilter('all');
      setMitigationSearch('');
      setMitigationCategoryFilter('all');
    }
  }, [selectedFramework]);

  const loadFrameworks = async () => {
    try {
      setLoading(true);
      const response = await frameworksApi.list();
      setFrameworks(response.data);
      if (response.data.length > 0) {
        setSelectedFramework(response.data[0].id);
      }
    } catch (error) {
      console.error('Error loading frameworks:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadThreats = async (frameworkId: number) => {
    try {
      const response = await threatsApi.list({ framework_id: frameworkId });
      setThreats(response.data);
    } catch (error) {
      console.error('Error loading threats:', error);
    }
  };

  const loadMitigations = async (frameworkId: number) => {
    try {
      const response = await mitigationsApi.list({ framework_id: frameworkId });
      setMitigations(response.data);
    } catch (error) {
      console.error('Error loading mitigations:', error);
    }
  };

  const loadCWEs = async () => {
    try {
      setLoadingCWEs(true);
      const response = await cwesApi.list();
      setCWEs(response.data);
    } catch (error) {
      console.error('Error loading CWEs:', error);
    } finally {
      setLoadingCWEs(false);
    }
  };

  // Threat handlers
  const handleCreateThreat = async () => {
    if (!selectedFramework) return;
    try {
      await threatsApi.create({
        ...threatForm,
        framework_id: selectedFramework,
      });
      setThreatDialogOpen(false);
      setThreatForm({ name: '', description: '', category: '' });
      loadThreats(selectedFramework);
    } catch (error) {
      console.error('Error creating threat:', error);
    }
  };

  const handleUpdateThreat = async () => {
    if (!editingThreat) return;
    try {
      await threatsApi.update(editingThreat.id, threatForm);
      setThreatDialogOpen(false);
      setEditingThreat(null);
      setThreatForm({ name: '', description: '', category: '' });
      if (selectedFramework) loadThreats(selectedFramework);
    } catch (error) {
      console.error('Error updating threat:', error);
    }
  };

  const openDeleteThreatDialog = (threat: Threat) => {
    if (!threat.is_custom) {
      alert('Cannot delete pre-defined threats');
      return;
    }
    setThreatToDelete(threat);
    setDeleteThreatOpen(true);
  };

  const handleDeleteThreat = async () => {
    if (!threatToDelete) return;
    try {
      await threatsApi.delete(threatToDelete.id);
      setDeleteThreatOpen(false);
      setThreatToDelete(null);
      if (selectedFramework) loadThreats(selectedFramework);
    } catch (error) {
      console.error('Error deleting threat:', error);
    }
  };

  const openThreatDialog = (threat?: Threat) => {
    if (threat) {
      setEditingThreat(threat);
      setThreatForm({
        name: threat.name,
        description: threat.description,
        category: threat.category,
      });
    } else {
      setEditingThreat(null);
      setThreatForm({ name: '', description: '', category: '' });
    }
    setThreatDialogOpen(true);
  };

  // Threat detail sheet handlers
  const handleOpenThreatDetail = async (threat: Threat) => {
    setSelectedThreat(threat);
    setEditDescription(threat.description || '');
    setThreatDetailOpen(true);
    setLoadingThreatCWEs(true);
    try {
      const response = await cwesApi.getForThreat(threat.id);
      setThreatCWEs(response.data);
    } catch (error) {
      console.error('Error loading CWEs for threat:', error);
      setThreatCWEs([]);
    } finally {
      setLoadingThreatCWEs(false);
    }
  };

  const handleSaveThreatDescription = async () => {
    if (!selectedThreat) return;
    setSavingDescription(true);
    try {
      await threatsApi.update(selectedThreat.id, { description: editDescription });
      // Update local state
      setThreats(prev => prev.map(t => t.id === selectedThreat.id ? { ...t, description: editDescription } : t));
      setSelectedThreat({ ...selectedThreat, description: editDescription });
    } catch (error) {
      console.error('Error saving threat description:', error);
    } finally {
      setSavingDescription(false);
    }
  };

  // Related mitigations for a threat (same framework + category)
  const getRelatedMitigations = (threat: Threat) => {
    return mitigations.filter(
      m => m.framework_id === threat.framework_id && m.category === threat.category
    );
  };

  // Mitigation handlers
  const handleCreateMitigation = async () => {
    if (!selectedFramework) return;
    try {
      await mitigationsApi.create({
        ...mitigationForm,
        framework_id: selectedFramework,
      });
      setMitigationDialogOpen(false);
      setMitigationForm({ name: '', description: '', category: '' });
      loadMitigations(selectedFramework);
    } catch (error) {
      console.error('Error creating mitigation:', error);
    }
  };

  const handleUpdateMitigation = async () => {
    if (!editingMitigation) return;
    try {
      await mitigationsApi.update(editingMitigation.id, mitigationForm);
      setMitigationDialogOpen(false);
      setEditingMitigation(null);
      setMitigationForm({ name: '', description: '', category: '' });
      if (selectedFramework) loadMitigations(selectedFramework);
    } catch (error) {
      console.error('Error updating mitigation:', error);
    }
  };

  const openDeleteMitigationDialog = (mitigation: Mitigation) => {
    if (!mitigation.is_custom) {
      alert('Cannot delete pre-defined mitigations');
      return;
    }
    setMitigationToDelete(mitigation);
    setDeleteMitigationOpen(true);
  };

  const handleDeleteMitigation = async () => {
    if (!mitigationToDelete) return;
    try {
      await mitigationsApi.delete(mitigationToDelete.id);
      setDeleteMitigationOpen(false);
      setMitigationToDelete(null);
      if (selectedFramework) loadMitigations(selectedFramework);
    } catch (error) {
      console.error('Error deleting mitigation:', error);
    }
  };

  const openMitigationDialog = (mitigation?: Mitigation) => {
    if (mitigation) {
      setEditingMitigation(mitigation);
      setMitigationForm({
        name: mitigation.name,
        description: mitigation.description,
        category: mitigation.category,
      });
    } else {
      setEditingMitigation(null);
      setMitigationForm({ name: '', description: '', category: '' });
    }
    setMitigationDialogOpen(true);
  };

  // Mitigation detail sheet handlers
  const handleOpenMitigationDetail = async (mitigation: Mitigation) => {
    setSelectedMitigation(mitigation);
    setEditMitigationDescription(mitigation.description || '');
    setMitigationDetailOpen(true);
  };

  const handleSaveMitigationDescription = async () => {
    if (!selectedMitigation) return;
    setSavingMitigationDescription(true);
    try {
      await mitigationsApi.update(selectedMitigation.id, { description: editMitigationDescription });
      setMitigations(prev => prev.map(m => m.id === selectedMitigation.id ? { ...m, description: editMitigationDescription } : m));
      setSelectedMitigation({ ...selectedMitigation, description: editMitigationDescription });
    } catch (error) {
      console.error('Error saving mitigation description:', error);
    } finally {
      setSavingMitigationDescription(false);
    }
  };

  // Related threats for a mitigation (same framework + category)
  const getRelatedThreats = (mitigation: Mitigation) => {
    return threats.filter(
      t => t.framework_id === mitigation.framework_id && t.category === mitigation.category
    );
  };

  // CWE detail handler
  const handleOpenCweDetail = async (cwe: CWE) => {
    setSelectedCWE(cwe);
    setCweDetailOpen(true);
    setLoadingCweThreats(true);
    try {
      // Find threats linked to this CWE by checking each threat's CWEs
      // We'll use a simpler approach: check all threats loaded for the selected framework
      const linkedThreats: Threat[] = [];
      for (const threat of threats) {
        try {
          const resp = await cwesApi.getForThreat(threat.id);
          const threatCweIds = resp.data.map((c: CWE) => c.id);
          if (threatCweIds.includes(cwe.id)) {
            linkedThreats.push(threat);
          }
        } catch {
          // skip
        }
      }
      setCweThreatLinks(linkedThreats);
    } catch (error) {
      console.error('Error loading threats for CWE:', error);
      setCweThreatLinks([]);
    } finally {
      setLoadingCweThreats(false);
    }
  };

  // Unique categories (for filter selects and create/edit forms)
  const threatCategories = Array.from(new Set(threats.map(t => t.category).filter(Boolean))).sort();
  const mitigationCategories = Array.from(new Set(mitigations.map(m => m.category).filter(Boolean))).sort();

  // Filtered lists
  const filteredThreats = threats.filter(t => {
    const matchesSearch =
      t.name.toLowerCase().includes(threatSearch.toLowerCase()) ||
      t.description.toLowerCase().includes(threatSearch.toLowerCase()) ||
      t.category.toLowerCase().includes(threatSearch.toLowerCase());
    const matchesCategory = threatCategoryFilter === 'all' || t.category === threatCategoryFilter;
    return matchesSearch && matchesCategory;
  });

  const filteredMitigations = mitigations.filter(m => {
    const matchesSearch =
      m.name.toLowerCase().includes(mitigationSearch.toLowerCase()) ||
      m.description.toLowerCase().includes(mitigationSearch.toLowerCase()) ||
      m.category.toLowerCase().includes(mitigationSearch.toLowerCase());
    const matchesCategory = mitigationCategoryFilter === 'all' || m.category === mitigationCategoryFilter;
    return matchesSearch && matchesCategory;
  });

  // CWE filtered list
  const filteredCWEs = cwes.filter(c => {
    if (!cweSearch) return true;
    const search = cweSearch.toLowerCase();
    return (
      c.cwe_id.toLowerCase().includes(search) ||
      c.name.toLowerCase().includes(search) ||
      (c.category && c.category.toLowerCase().includes(search)) ||
      (c.description && c.description.toLowerCase().includes(search))
    );
  });

  // Helper to get framework name
  const getFrameworkName = (frameworkId: number) => {
    const fw = frameworks.find(f => f.id === frameworkId);
    return fw ? fw.name : 'Unknown';
  };

  // Severity color helper
  const getSeverityColor = (severity: string | null) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-green-100 text-green-800 border-green-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  return (
    <div className="flex-1 space-y-6 mx-auto p-4">

      {loading ? (
          <Card className="border-dashed rounded-xl animate-pulse">
            <CardContent className="flex items-center justify-center p-16">
              <div className="flex flex-col items-center gap-3">
                <div className="h-10 w-10 animate-spin rounded-full border-4 border-primary border-t-transparent" />
                <p className="text-sm text-muted-foreground font-medium">Loading knowledge base...</p>
              </div>
            </CardContent>
        </Card>
      ) : (
        <div className="space-y-5">
          {/* Framework Selection */}
          <div className="grid gap-4 sm:grid-cols-1 md:grid-cols-2">
              {frameworks.map((framework, index) => {
                const isSelected = selectedFramework === framework.id;
                return (
                  <Card
                    key={framework.id}
                    className={`cursor-pointer transition-all duration-300 hover:shadow-lg rounded-xl group ${
                      isSelected ? 'border-primary/60 ring-2 ring-primary/50 ring-offset-2 shadow-md' : 'hover:border-primary/30'
                    }`}
                    onClick={() => setSelectedFramework(framework.id)}
                    style={{
                      animation: 'slideUp 0.5s ease-out forwards',
                      animationDelay: `${index * 100}ms`,
                      opacity: 0
                    }}
                  >
                    <CardContent className="p-5">
                      <div className="flex items-start gap-4">
                        <div className={`flex h-12 w-12 items-center justify-center rounded-xl shrink-0 shadow-sm transition-all duration-300 ${
                          isSelected
                            ? 'bg-primary text-primary-foreground shadow-lg scale-110'
                            : 'bg-primary/10 text-primary group-hover:bg-primary/15 group-hover:scale-105'
                        }`}>
                          <Library className={`h-5 w-5 transition-transform duration-300 ${isSelected ? 'rotate-12' : 'group-hover:rotate-12'}`} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <h3 className="font-bold text-base mb-1.5 bg-gradient-to-r from-foreground to-foreground/80 bg-clip-text">
                            {framework.name}
                          </h3>
                          <p className="text-sm text-muted-foreground line-clamp-2 leading-relaxed font-medium">
                            {framework.description}
                          </p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
            })}
          </div>

          {/* Threats, Mitigations, and CWEs Tabs */}
          <Tabs defaultValue="threats" className="w-full space-y-4">
            <TabsList className="grid w-full max-w-[630px] grid-cols-3 h-11 p-1 rounded-xl shadow-sm">
                  <TabsTrigger value="threats" className="gap-2 rounded-lg font-semibold transition-all duration-200 data-[state=active]:shadow-sm">
                    <AlertTriangle className="h-4 w-4" />
                    Threats ({threats.length})
                  </TabsTrigger>
                  <TabsTrigger value="mitigations" className="gap-2 rounded-lg font-semibold transition-all duration-200 data-[state=active]:shadow-sm">
                    <Shield className="h-4 w-4" />
                    Mitigations ({mitigations.length})
                  </TabsTrigger>
                  <TabsTrigger value="cwes" className="gap-2 rounded-lg font-semibold transition-all duration-200 data-[state=active]:shadow-sm">
                    <Bug className="h-4 w-4" />
                    CWEs ({cwes.length})
                  </TabsTrigger>
            </TabsList>

            <TabsContent value="threats" className="space-y-3 animate-fadeIn">
                {/* Filter bar */}
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      placeholder="Search threats..."
                      value={threatSearch}
                      onChange={(e) => setThreatSearch(e.target.value)}
                      className="pl-9 rounded-lg border-border/60"
                    />
                    {threatSearch && (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 p-0 rounded-md"
                        onClick={() => setThreatSearch('')}
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                  <Select
                    value={threatCategoryFilter}
                    onValueChange={setThreatCategoryFilter}
                    disabled={threatCategories.length === 0}
                  >
                    <SelectTrigger className="w-44 rounded-lg border-border/60">
                      <SelectValue placeholder="All Categories" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Categories</SelectItem>
                      {threatCategories.map((cat) => (
                        <SelectItem key={cat} value={cat}>{cat}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {canWrite && (
                    <Button
                      onClick={() => openThreatDialog()}
                      size="sm"
                      className="shadow-sm hover:shadow-md transition-all duration-200 hover:scale-105 rounded-lg font-semibold shrink-0"
                    >
                      <Plus className="h-4 w-4 mr-2" />
                      Add Custom Threat
                    </Button>
                  )}
                </div>

                {/* Active filter chips */}
                {(threatSearch || threatCategoryFilter !== 'all') && (
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs text-muted-foreground font-medium">Filters:</span>
                    {threatCategoryFilter !== 'all' && (
                      <button
                        onClick={() => setThreatCategoryFilter('all')}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20 transition-colors"
                      >
                        {threatCategoryFilter}
                        <X className="h-3 w-3" />
                      </button>
                    )}
                    {threatSearch && (
                      <button
                        onClick={() => setThreatSearch('')}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20 transition-colors"
                      >
                        "{threatSearch}"
                        <X className="h-3 w-3" />
                      </button>
                    )}
                    <span className="text-xs text-muted-foreground">
                      — {filteredThreats.length} result{filteredThreats.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                )}

                {threats.length === 0 ? (
                  <Card className="border-dashed border-2 rounded-xl">
                    <CardContent className="flex flex-col items-center justify-center p-16">
                      <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-orange-500/10 to-orange-500/5 mb-4 shadow-sm">
                        <AlertTriangle className="h-8 w-8 text-orange-600" />
                      </div>
                      <h3 className="text-lg font-bold mb-2">No threats available</h3>
                      <p className="text-sm text-muted-foreground text-center max-w-sm leading-relaxed">
                        This framework doesn't have any threats defined yet.
                      </p>
                    </CardContent>
                  </Card>
                ) : filteredThreats.length === 0 ? (
                  <Card className="border-dashed rounded-xl">
                    <CardContent className="flex flex-col items-center justify-center p-12">
                      <Search className="h-8 w-8 text-muted-foreground mb-3" />
                      <h3 className="text-base font-bold mb-1">No threats match your filters</h3>
                      <p className="text-sm text-muted-foreground text-center">
                        Try adjusting your search or category filter.
                      </p>
                    </CardContent>
                  </Card>
                ) : (
                  <Card className="rounded-xl border-border/60 shadow-sm overflow-hidden">
                    <CardContent className="p-0">
                      <Table>
                        <TableHeader>
                          <TableRow className="hover:bg-transparent border-b border-border/60">
                            <TableHead className="w-[50px]"></TableHead>
                            <TableHead className="font-bold text-foreground/90">Name</TableHead>
                            <TableHead className="font-bold text-foreground/90">Category</TableHead>
                            <TableHead className="font-bold text-foreground/90">Description</TableHead>
                            <TableHead className="w-[120px] font-bold text-foreground/90">Type</TableHead>
                            <TableHead className="w-[50px]"></TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {filteredThreats.map((threat, index) => (
                            <TableRow
                              key={threat.id}
                              className="hover:bg-muted/50 transition-colors border-b border-border/40 last:border-0 cursor-pointer"
                              style={{
                                animation: 'fadeIn 0.3s ease-out forwards',
                                animationDelay: `${index * 30}ms`,
                                opacity: 0
                              }}
                              onClick={() => handleOpenThreatDetail(threat)}
                            >
                              <TableCell>
                                <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-orange-500/10 to-orange-500/5 shadow-sm">
                                  <AlertTriangle className="h-4 w-4 text-orange-600" />
                                </div>
                              </TableCell>
                              <TableCell className="font-semibold">{threat.name}</TableCell>
                              <TableCell>
                                <Badge variant="outline" className="font-medium shadow-sm rounded-lg">{threat.category}</Badge>
                              </TableCell>
                              <TableCell className="text-sm text-muted-foreground max-w-md font-medium">
                                {threat.description}
                              </TableCell>
                              <TableCell>
                                <Badge variant={threat.is_custom ? 'default' : 'secondary'} className="gap-1.5 font-semibold shadow-sm rounded-lg">
                                  {threat.is_custom && <Sparkles className="h-3 w-3" />}
                                  {threat.is_custom ? 'Custom' : 'Predefined'}
                                </Badge>
                              </TableCell>
                              <TableCell onClick={(e) => e.stopPropagation()}>
                                {canWrite && (
                                  <DropdownMenu>
                                    <DropdownMenuTrigger asChild>
                                      <Button variant="ghost" size="sm" className="h-8 w-8 p-0 hover:bg-muted transition-all rounded-lg">
                                        <MoreVertical className="h-4 w-4" />
                                      </Button>
                                    </DropdownMenuTrigger>
                                    <DropdownMenuContent align="end" className="w-48">
                                      <DropdownMenuItem onClick={() => handleOpenThreatDetail(threat)} className="cursor-pointer">
                                        <Eye className="mr-2 h-4 w-4" />
                                        View Details
                                      </DropdownMenuItem>
                                      {threat.is_custom ? (
                                        <>
                                          <DropdownMenuItem onClick={() => openThreatDialog(threat)} className="cursor-pointer">
                                            <Pencil className="mr-2 h-4 w-4" />
                                            Edit
                                          </DropdownMenuItem>
                                          <DropdownMenuSeparator />
                                          <DropdownMenuItem
                                            onClick={() => openDeleteThreatDialog(threat)}
                                            className="text-destructive cursor-pointer focus:text-destructive"
                                          >
                                            <Trash2 className="mr-2 h-4 w-4" />
                                            Delete
                                          </DropdownMenuItem>
                                        </>
                                      ) : (
                                        <DropdownMenuItem onClick={() => handleOpenThreatDetail(threat)} className="cursor-pointer">
                                          <FileText className="mr-2 h-4 w-4" />
                                          Edit Description
                                        </DropdownMenuItem>
                                      )}
                                    </DropdownMenuContent>
                                  </DropdownMenu>
                                )}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </CardContent>
                  </Card>
                )}
            </TabsContent>

            <TabsContent value="mitigations" className="space-y-3 animate-fadeIn">
                {/* Filter bar */}
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      placeholder="Search mitigations..."
                      value={mitigationSearch}
                      onChange={(e) => setMitigationSearch(e.target.value)}
                      className="pl-9 rounded-lg border-border/60"
                    />
                    {mitigationSearch && (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 p-0 rounded-md"
                        onClick={() => setMitigationSearch('')}
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                  <Select
                    value={mitigationCategoryFilter}
                    onValueChange={setMitigationCategoryFilter}
                    disabled={mitigationCategories.length === 0}
                  >
                    <SelectTrigger className="w-44 rounded-lg border-border/60">
                      <SelectValue placeholder="All Categories" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Categories</SelectItem>
                      {mitigationCategories.map((cat) => (
                        <SelectItem key={cat} value={cat}>{cat}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {canWrite && (
                    <Button
                      onClick={() => openMitigationDialog()}
                      size="sm"
                      className="shadow-sm hover:shadow-md transition-all duration-200 hover:scale-105 rounded-lg font-semibold shrink-0"
                    >
                      <Plus className="h-4 w-4 mr-2" />
                      Add Custom Mitigation
                    </Button>
                  )}
                </div>

                {/* Active filter chips */}
                {(mitigationSearch || mitigationCategoryFilter !== 'all') && (
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs text-muted-foreground font-medium">Filters:</span>
                    {mitigationCategoryFilter !== 'all' && (
                      <button
                        onClick={() => setMitigationCategoryFilter('all')}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20 transition-colors"
                      >
                        {mitigationCategoryFilter}
                        <X className="h-3 w-3" />
                      </button>
                    )}
                    {mitigationSearch && (
                      <button
                        onClick={() => setMitigationSearch('')}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20 transition-colors"
                      >
                        "{mitigationSearch}"
                        <X className="h-3 w-3" />
                      </button>
                    )}
                    <span className="text-xs text-muted-foreground">
                      — {filteredMitigations.length} result{filteredMitigations.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                )}

                {mitigations.length === 0 ? (
                  <Card className="border-dashed border-2 rounded-xl">
                    <CardContent className="flex flex-col items-center justify-center p-16">
                      <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-green-500/10 to-green-500/5 mb-4 shadow-sm">
                        <Shield className="h-8 w-8 text-green-600" />
                      </div>
                      <h3 className="text-lg font-bold mb-2">No mitigations available</h3>
                      <p className="text-sm text-muted-foreground text-center max-w-sm leading-relaxed">
                        This framework doesn't have any mitigations defined yet.
                      </p>
                    </CardContent>
                  </Card>
                ) : filteredMitigations.length === 0 ? (
                  <Card className="border-dashed rounded-xl">
                    <CardContent className="flex flex-col items-center justify-center p-12">
                      <Search className="h-8 w-8 text-muted-foreground mb-3" />
                      <h3 className="text-base font-bold mb-1">No mitigations match your filters</h3>
                      <p className="text-sm text-muted-foreground text-center">
                        Try adjusting your search or category filter.
                      </p>
                    </CardContent>
                  </Card>
                ) : (
                  <Card className="rounded-xl border-border/60 shadow-sm overflow-hidden">
                    <CardContent className="p-0">
                      <Table>
                        <TableHeader>
                          <TableRow className="hover:bg-transparent border-b border-border/60">
                            <TableHead className="w-[50px]"></TableHead>
                            <TableHead className="font-bold text-foreground/90">Name</TableHead>
                            <TableHead className="font-bold text-foreground/90">Category</TableHead>
                            <TableHead className="font-bold text-foreground/90">Description</TableHead>
                            <TableHead className="w-[120px] font-bold text-foreground/90">Type</TableHead>
                            <TableHead className="w-[50px]"></TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {filteredMitigations.map((mitigation, index) => (
                            <TableRow
                              key={mitigation.id}
                              className="hover:bg-muted/50 transition-colors border-b border-border/40 last:border-0 cursor-pointer"
                              style={{
                                animation: 'fadeIn 0.3s ease-out forwards',
                                animationDelay: `${index * 30}ms`,
                                opacity: 0
                              }}
                              onClick={() => handleOpenMitigationDetail(mitigation)}
                            >
                              <TableCell>
                                <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-green-500/10 to-green-500/5 shadow-sm">
                                  <Shield className="h-4 w-4 text-green-600" />
                                </div>
                              </TableCell>
                              <TableCell className="font-semibold">{mitigation.name}</TableCell>
                              <TableCell>
                                <Badge variant="outline" className="font-medium shadow-sm rounded-lg">{mitigation.category}</Badge>
                              </TableCell>
                              <TableCell className="text-sm text-muted-foreground max-w-md font-medium">
                                {mitigation.description}
                              </TableCell>
                              <TableCell>
                                <Badge variant={mitigation.is_custom ? 'default' : 'secondary'} className="gap-1.5 font-semibold shadow-sm rounded-lg">
                                  {mitigation.is_custom && <Sparkles className="h-3 w-3" />}
                                  {mitigation.is_custom ? 'Custom' : 'Predefined'}
                                </Badge>
                              </TableCell>
                              <TableCell onClick={(e) => e.stopPropagation()}>
                                {canWrite && (
                                  <DropdownMenu>
                                    <DropdownMenuTrigger asChild>
                                      <Button variant="ghost" size="sm" className="h-8 w-8 p-0 hover:bg-muted transition-all rounded-lg">
                                        <MoreVertical className="h-4 w-4" />
                                      </Button>
                                    </DropdownMenuTrigger>
                                    <DropdownMenuContent align="end" className="w-48">
                                      <DropdownMenuItem onClick={() => handleOpenMitigationDetail(mitigation)} className="cursor-pointer">
                                        <Eye className="mr-2 h-4 w-4" />
                                        View Details
                                      </DropdownMenuItem>
                                      {mitigation.is_custom ? (
                                        <>
                                          <DropdownMenuItem onClick={() => openMitigationDialog(mitigation)} className="cursor-pointer">
                                            <Pencil className="mr-2 h-4 w-4" />
                                            Edit
                                          </DropdownMenuItem>
                                          <DropdownMenuSeparator />
                                          <DropdownMenuItem
                                            onClick={() => openDeleteMitigationDialog(mitigation)}
                                            className="text-destructive cursor-pointer focus:text-destructive"
                                          >
                                            <Trash2 className="mr-2 h-4 w-4" />
                                            Delete
                                          </DropdownMenuItem>
                                        </>
                                      ) : (
                                        <DropdownMenuItem onClick={() => handleOpenMitigationDetail(mitigation)} className="cursor-pointer">
                                          <FileText className="mr-2 h-4 w-4" />
                                          Edit Description
                                        </DropdownMenuItem>
                                      )}
                                    </DropdownMenuContent>
                                  </DropdownMenu>
                                )}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </CardContent>
                  </Card>
                )}
            </TabsContent>

            {/* CWEs Tab */}
            <TabsContent value="cwes" className="space-y-3 animate-fadeIn">
                {/* Filter bar */}
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      placeholder="Search CWEs by ID, name, or category..."
                      value={cweSearch}
                      onChange={(e) => setCweSearch(e.target.value)}
                      className="pl-9 rounded-lg border-border/60"
                    />
                    {cweSearch && (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 p-0 rounded-md"
                        onClick={() => setCweSearch('')}
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                </div>

                {/* Active filter chips */}
                {cweSearch && (
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs text-muted-foreground font-medium">Filters:</span>
                    <button
                      onClick={() => setCweSearch('')}
                      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20 transition-colors"
                    >
                      "{cweSearch}"
                      <X className="h-3 w-3" />
                    </button>
                    <span className="text-xs text-muted-foreground">
                      — {filteredCWEs.length} result{filteredCWEs.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                )}

                {loadingCWEs ? (
                  <Card className="border-dashed rounded-xl animate-pulse">
                    <CardContent className="flex items-center justify-center p-16">
                      <div className="flex flex-col items-center gap-3">
                        <div className="h-10 w-10 animate-spin rounded-full border-4 border-primary border-t-transparent" />
                        <p className="text-sm text-muted-foreground font-medium">Loading CWEs...</p>
                      </div>
                    </CardContent>
                  </Card>
                ) : cwes.length === 0 ? (
                  <Card className="border-dashed border-2 rounded-xl">
                    <CardContent className="flex flex-col items-center justify-center p-16">
                      <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-purple-500/10 to-purple-500/5 mb-4 shadow-sm">
                        <Bug className="h-8 w-8 text-purple-600" />
                      </div>
                      <h3 className="text-lg font-bold mb-2">No CWEs available</h3>
                      <p className="text-sm text-muted-foreground text-center max-w-sm leading-relaxed">
                        CWE data has not been seeded yet. CWEs are populated from MITRE data.
                      </p>
                    </CardContent>
                  </Card>
                ) : filteredCWEs.length === 0 ? (
                  <Card className="border-dashed rounded-xl">
                    <CardContent className="flex flex-col items-center justify-center p-12">
                      <Search className="h-8 w-8 text-muted-foreground mb-3" />
                      <h3 className="text-base font-bold mb-1">No CWEs match your search</h3>
                      <p className="text-sm text-muted-foreground text-center">
                        Try adjusting your search query.
                      </p>
                    </CardContent>
                  </Card>
                ) : (
                  <Card className="rounded-xl border-border/60 shadow-sm overflow-hidden">
                    <CardContent className="p-0">
                      <Table>
                        <TableHeader>
                          <TableRow className="hover:bg-transparent border-b border-border/60">
                            <TableHead className="w-[50px]"></TableHead>
                            <TableHead className="w-[120px] font-bold text-foreground/90">CWE ID</TableHead>
                            <TableHead className="font-bold text-foreground/90">Name</TableHead>
                            <TableHead className="font-bold text-foreground/90">Category</TableHead>
                            <TableHead className="w-[100px] font-bold text-foreground/90">Severity</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {filteredCWEs.map((cwe, index) => (
                            <TableRow
                              key={cwe.id}
                              className="hover:bg-muted/50 transition-colors border-b border-border/40 last:border-0 cursor-pointer"
                              style={{
                                animation: 'fadeIn 0.3s ease-out forwards',
                                animationDelay: `${index * 30}ms`,
                                opacity: 0
                              }}
                              onClick={() => handleOpenCweDetail(cwe)}
                            >
                              <TableCell>
                                <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-purple-500/10 to-purple-500/5 shadow-sm">
                                  <Bug className="h-4 w-4 text-purple-600" />
                                </div>
                              </TableCell>
                              <TableCell>
                                <Badge variant="outline" className="font-mono font-semibold shadow-sm rounded-lg">{cwe.cwe_id}</Badge>
                              </TableCell>
                              <TableCell className="font-semibold">{cwe.name}</TableCell>
                              <TableCell>
                                {cwe.category && (
                                  <Badge variant="outline" className="font-medium shadow-sm rounded-lg">{cwe.category}</Badge>
                                )}
                              </TableCell>
                              <TableCell>
                                {cwe.severity && (
                                  <Badge className={`font-semibold shadow-sm rounded-lg border ${getSeverityColor(cwe.severity)}`}>
                                    {cwe.severity.charAt(0).toUpperCase() + cwe.severity.slice(1)}
                                  </Badge>
                                )}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </CardContent>
                  </Card>
                )}
            </TabsContent>
          </Tabs>
        </div>
      )}

      {/* Threat Detail Sheet */}
      <Sheet open={threatDetailOpen} onOpenChange={setThreatDetailOpen}>
        <SheetContent className="sm:max-w-2xl overflow-y-auto">
          <SheetHeader>
            <SheetTitle className="text-lg font-bold">{selectedThreat?.name}</SheetTitle>
            <SheetDescription>Threat details and linked information</SheetDescription>
          </SheetHeader>
          {selectedThreat && (
            <div className="space-y-6 p-4 pt-2">
              {/* Badges row */}
              <div className="flex flex-wrap gap-2">
                <Badge variant="outline" className="font-medium shadow-sm rounded-lg">{selectedThreat.category}</Badge>
                <Badge variant={selectedThreat.is_custom ? 'default' : 'secondary'} className="gap-1.5 font-semibold shadow-sm rounded-lg">
                  {selectedThreat.is_custom && <Sparkles className="h-3 w-3" />}
                  {selectedThreat.is_custom ? 'Custom' : 'Predefined'}
                </Badge>
              </div>

              {/* Framework */}
              <div>
                <Label className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">Framework</Label>
                <p className="text-sm font-medium mt-1">{getFrameworkName(selectedThreat.framework_id)}</p>
              </div>

              {/* Name (editable for custom, read-only for predefined) */}
              <div>
                <Label className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">Name</Label>
                <p className="text-sm font-medium mt-1">{selectedThreat.name}</p>
              </div>

              {/* Description (editable for admin) */}
              <div>
                <Label className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">Description</Label>
                {canWrite ? (
                  <div className="mt-1 space-y-2">
                    <Textarea
                      value={editDescription}
                      onChange={(e) => setEditDescription(e.target.value)}
                      rows={5}
                      className="text-sm"
                      placeholder="Enter a description..."
                    />
                    {editDescription !== (selectedThreat.description || '') && (
                      <Button
                        size="sm"
                        onClick={handleSaveThreatDescription}
                        disabled={savingDescription}
                        className="font-semibold"
                      >
                        {savingDescription ? 'Saving...' : 'Save Description'}
                      </Button>
                    )}
                  </div>
                ) : (
                  <p className="text-sm mt-1 whitespace-pre-wrap">{selectedThreat.description || 'No description provided.'}</p>
                )}
              </div>

              {/* Linked CWEs */}
              <div>
                <Label className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">Linked CWEs</Label>
                <div className="mt-2 space-y-2">
                  {loadingThreatCWEs ? (
                    <p className="text-sm text-muted-foreground">Loading CWEs...</p>
                  ) : threatCWEs.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No CWEs linked to this threat.</p>
                  ) : (
                    threatCWEs.map((cwe) => (
                      <div
                        key={cwe.id}
                        className="flex items-center gap-2 p-2 rounded-lg border border-border/60 bg-muted/30 hover:bg-muted/50 transition-colors"
                      >
                        <Bug className="h-4 w-4 text-purple-600 shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="font-mono text-xs shadow-sm rounded-lg">{cwe.cwe_id}</Badge>
                            <span className="text-sm font-medium truncate">{cwe.name}</span>
                          </div>
                        </div>
                        {cwe.severity && (
                          <Badge className={`text-xs font-semibold shadow-sm rounded-lg border shrink-0 ${getSeverityColor(cwe.severity)}`}>
                            {cwe.severity.charAt(0).toUpperCase() + cwe.severity.slice(1)}
                          </Badge>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Related Mitigations */}
              <div>
                <Label className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">Related Mitigations</Label>
                <div className="mt-2 space-y-2">
                  {(() => {
                    const related = getRelatedMitigations(selectedThreat);
                    if (related.length === 0) {
                      return <p className="text-sm text-muted-foreground">No related mitigations found for this category.</p>;
                    }
                    return related.map((mit) => (
                      <div
                        key={mit.id}
                        className="flex items-center gap-2 p-2 rounded-lg border border-border/60 bg-muted/30 hover:bg-muted/50 transition-colors cursor-pointer"
                        onClick={() => {
                          setThreatDetailOpen(false);
                          setTimeout(() => handleOpenMitigationDetail(mit), 300);
                        }}
                      >
                        <Shield className="h-4 w-4 text-green-600 shrink-0" />
                        <div className="flex-1 min-w-0">
                          <span className="text-sm font-medium">{mit.name}</span>
                          <p className="text-xs text-muted-foreground truncate">{mit.description}</p>
                        </div>
                        <Badge variant={mit.is_custom ? 'default' : 'secondary'} className="text-xs shrink-0 rounded-lg">
                          {mit.is_custom ? 'Custom' : 'Predefined'}
                        </Badge>
                      </div>
                    ));
                  })()}
                </div>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* Mitigation Detail Sheet */}
      <Sheet open={mitigationDetailOpen} onOpenChange={setMitigationDetailOpen}>
        <SheetContent className="sm:max-w-2xl overflow-y-auto">
          <SheetHeader>
            <SheetTitle className="text-lg font-bold">{selectedMitigation?.name}</SheetTitle>
            <SheetDescription>Mitigation details and linked information</SheetDescription>
          </SheetHeader>
          {selectedMitigation && (
            <div className="space-y-6 p-4 pt-2">
              {/* Badges row */}
              <div className="flex flex-wrap gap-2">
                <Badge variant="outline" className="font-medium shadow-sm rounded-lg">{selectedMitigation.category}</Badge>
                <Badge variant={selectedMitigation.is_custom ? 'default' : 'secondary'} className="gap-1.5 font-semibold shadow-sm rounded-lg">
                  {selectedMitigation.is_custom && <Sparkles className="h-3 w-3" />}
                  {selectedMitigation.is_custom ? 'Custom' : 'Predefined'}
                </Badge>
              </div>

              {/* Framework */}
              <div>
                <Label className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">Framework</Label>
                <p className="text-sm font-medium mt-1">{getFrameworkName(selectedMitigation.framework_id)}</p>
              </div>

              {/* Name */}
              <div>
                <Label className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">Name</Label>
                <p className="text-sm font-medium mt-1">{selectedMitigation.name}</p>
              </div>

              {/* Description (editable for admin) */}
              <div>
                <Label className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">Description</Label>
                {canWrite ? (
                  <div className="mt-1 space-y-2">
                    <Textarea
                      value={editMitigationDescription}
                      onChange={(e) => setEditMitigationDescription(e.target.value)}
                      rows={5}
                      className="text-sm"
                      placeholder="Enter a description..."
                    />
                    {editMitigationDescription !== (selectedMitigation.description || '') && (
                      <Button
                        size="sm"
                        onClick={handleSaveMitigationDescription}
                        disabled={savingMitigationDescription}
                        className="font-semibold"
                      >
                        {savingMitigationDescription ? 'Saving...' : 'Save Description'}
                      </Button>
                    )}
                  </div>
                ) : (
                  <p className="text-sm mt-1 whitespace-pre-wrap">{selectedMitigation.description || 'No description provided.'}</p>
                )}
              </div>

              {/* Related Threats */}
              <div>
                <Label className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">Related Threats</Label>
                <div className="mt-2 space-y-2">
                  {(() => {
                    const related = getRelatedThreats(selectedMitigation);
                    if (related.length === 0) {
                      return <p className="text-sm text-muted-foreground">No related threats found for this category.</p>;
                    }
                    return related.map((thr) => (
                      <div
                        key={thr.id}
                        className="flex items-center gap-2 p-2 rounded-lg border border-border/60 bg-muted/30 hover:bg-muted/50 transition-colors cursor-pointer"
                        onClick={() => {
                          setMitigationDetailOpen(false);
                          setTimeout(() => handleOpenThreatDetail(thr), 300);
                        }}
                      >
                        <AlertTriangle className="h-4 w-4 text-orange-600 shrink-0" />
                        <div className="flex-1 min-w-0">
                          <span className="text-sm font-medium">{thr.name}</span>
                          <p className="text-xs text-muted-foreground truncate">{thr.description}</p>
                        </div>
                        <Badge variant={thr.is_custom ? 'default' : 'secondary'} className="text-xs shrink-0 rounded-lg">
                          {thr.is_custom ? 'Custom' : 'Predefined'}
                        </Badge>
                      </div>
                    ));
                  })()}
                </div>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* CWE Detail Sheet */}
      <Sheet open={cweDetailOpen} onOpenChange={setCweDetailOpen}>
        <SheetContent className="sm:max-w-2xl overflow-y-auto">
          <SheetHeader>
            <SheetTitle className="text-lg font-bold">{selectedCWE?.cwe_id}: {selectedCWE?.name}</SheetTitle>
            <SheetDescription>CWE details from MITRE database</SheetDescription>
          </SheetHeader>
          {selectedCWE && (
            <div className="space-y-6 p-4 pt-2">
              {/* Badges row */}
              <div className="flex flex-wrap gap-2">
                <Badge variant="outline" className="font-mono font-semibold shadow-sm rounded-lg">{selectedCWE.cwe_id}</Badge>
                {selectedCWE.category && (
                  <Badge variant="outline" className="font-medium shadow-sm rounded-lg">{selectedCWE.category}</Badge>
                )}
                {selectedCWE.severity && (
                  <Badge className={`font-semibold shadow-sm rounded-lg border ${getSeverityColor(selectedCWE.severity)}`}>
                    {selectedCWE.severity.charAt(0).toUpperCase() + selectedCWE.severity.slice(1)}
                  </Badge>
                )}
              </div>

              {/* Description */}
              <div>
                <Label className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">Description</Label>
                <p className="text-sm mt-1 whitespace-pre-wrap">{selectedCWE.description || 'No description available.'}</p>
              </div>

              {/* MITRE Link */}
              {selectedCWE.url && (
                <div>
                  <Label className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">MITRE Reference</Label>
                  <a
                    href={selectedCWE.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 mt-1 text-sm text-primary hover:underline font-medium"
                  >
                    <ExternalLink className="h-4 w-4" />
                    View on MITRE
                  </a>
                </div>
              )}

              {/* Linked Threats */}
              <div>
                <Label className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">Linked Threats</Label>
                <div className="mt-2 space-y-2">
                  {loadingCweThreats ? (
                    <p className="text-sm text-muted-foreground">Loading linked threats...</p>
                  ) : cweThreatLinks.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No threats are linked to this CWE.</p>
                  ) : (
                    cweThreatLinks.map((thr) => (
                      <div
                        key={thr.id}
                        className="flex items-center gap-2 p-2 rounded-lg border border-border/60 bg-muted/30 hover:bg-muted/50 transition-colors cursor-pointer"
                        onClick={() => {
                          setCweDetailOpen(false);
                          setTimeout(() => handleOpenThreatDetail(thr), 300);
                        }}
                      >
                        <AlertTriangle className="h-4 w-4 text-orange-600 shrink-0" />
                        <div className="flex-1 min-w-0">
                          <span className="text-sm font-medium">{thr.name}</span>
                          <p className="text-xs text-muted-foreground truncate">{thr.description}</p>
                        </div>
                        <Badge variant="outline" className="text-xs shrink-0 rounded-lg">{thr.category}</Badge>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* Threat Dialog */}
      <Dialog open={threatDialogOpen} onOpenChange={setThreatDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editingThreat ? 'Edit Threat' : 'Add Custom Threat'}</DialogTitle>
            <DialogDescription>
              {editingThreat ? 'Update threat information.' : 'Create a custom threat for this framework.'}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 py-3">
            <div className="grid gap-2">
              <Label htmlFor="threat-name">Name</Label>
              <Input
                id="threat-name"
                value={threatForm.name}
                onChange={(e) => setThreatForm({ ...threatForm, name: e.target.value })}
                placeholder="Enter threat name"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="threat-category">Category</Label>
              {threatCategories.length > 0 ? (
                <>
                  <Select
                    value={threatCategories.includes(threatForm.category) ? threatForm.category : '__custom__'}
                    onValueChange={(value) => {
                      if (value !== '__custom__') {
                        setThreatForm({ ...threatForm, category: value });
                      }
                    }}
                  >
                    <SelectTrigger id="threat-category">
                      <SelectValue placeholder="Select a category" />
                    </SelectTrigger>
                    <SelectContent>
                      {threatCategories.map((category) => (
                        <SelectItem key={category} value={category}>
                          {category}
                        </SelectItem>
                      ))}
                      <SelectItem value="__custom__">Other (custom)</SelectItem>
                    </SelectContent>
                  </Select>
                  {!threatCategories.includes(threatForm.category) && (
                    <Input
                      placeholder="Enter custom category name"
                      value={threatForm.category}
                      onChange={(e) => setThreatForm({ ...threatForm, category: e.target.value })}
                      className="mt-2"
                    />
                  )}
                </>
              ) : (
                <Input
                  id="threat-category"
                  value={threatForm.category}
                  onChange={(e) => setThreatForm({ ...threatForm, category: e.target.value })}
                  placeholder="e.g., Spoofing, Tampering, etc."
                />
              )}
            </div>
            <div className="grid gap-2">
              <Label htmlFor="threat-description">Description</Label>
              <Textarea
                id="threat-description"
                value={threatForm.description}
                onChange={(e) => setThreatForm({ ...threatForm, description: e.target.value })}
                placeholder="Describe the threat in detail"
                rows={4}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setThreatDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={editingThreat ? handleUpdateThreat : handleCreateThreat}>
              {editingThreat ? 'Save Changes' : 'Create Threat'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Mitigation Dialog */}
      <Dialog open={mitigationDialogOpen} onOpenChange={setMitigationDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editingMitigation ? 'Edit Mitigation' : 'Add Custom Mitigation'}</DialogTitle>
            <DialogDescription>
              {editingMitigation ? 'Update mitigation information.' : 'Create a custom mitigation for this framework.'}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 py-3">
            <div className="grid gap-2">
              <Label htmlFor="mitigation-name">Name</Label>
              <Input
                id="mitigation-name"
                value={mitigationForm.name}
                onChange={(e) => setMitigationForm({ ...mitigationForm, name: e.target.value })}
                placeholder="Enter mitigation name"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="mitigation-category">Category</Label>
              {mitigationCategories.length > 0 ? (
                <>
                  <Select
                    value={mitigationCategories.includes(mitigationForm.category) ? mitigationForm.category : '__custom__'}
                    onValueChange={(value) => {
                      if (value !== '__custom__') {
                        setMitigationForm({ ...mitigationForm, category: value });
                      }
                    }}
                  >
                    <SelectTrigger id="mitigation-category">
                      <SelectValue placeholder="Select a category" />
                    </SelectTrigger>
                    <SelectContent>
                      {mitigationCategories.map((category) => (
                        <SelectItem key={category} value={category}>
                          {category}
                        </SelectItem>
                      ))}
                      <SelectItem value="__custom__">Other (custom)</SelectItem>
                    </SelectContent>
                  </Select>
                  {!mitigationCategories.includes(mitigationForm.category) && (
                    <Input
                      placeholder="Enter custom category name"
                      value={mitigationForm.category}
                      onChange={(e) => setMitigationForm({ ...mitigationForm, category: e.target.value })}
                      className="mt-2"
                    />
                  )}
                </>
              ) : (
                <Input
                  id="mitigation-category"
                  value={mitigationForm.category}
                  onChange={(e) => setMitigationForm({ ...mitigationForm, category: e.target.value })}
                  placeholder="e.g., Authentication, Encryption, etc."
                />
              )}
            </div>
            <div className="grid gap-2">
              <Label htmlFor="mitigation-description">Description</Label>
              <Textarea
                id="mitigation-description"
                value={mitigationForm.description}
                onChange={(e) => setMitigationForm({ ...mitigationForm, description: e.target.value })}
                placeholder="Describe the mitigation in detail"
                rows={4}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setMitigationDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={editingMitigation ? handleUpdateMitigation : handleCreateMitigation}>
              {editingMitigation ? 'Save Changes' : 'Create Mitigation'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Threat Alert Dialog */}
      <AlertDialog open={deleteThreatOpen} onOpenChange={setDeleteThreatOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Threat</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{threatToDelete?.name}"? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDeleteThreat} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete Mitigation Alert Dialog */}
      <AlertDialog open={deleteMitigationOpen} onOpenChange={setDeleteMitigationOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Mitigation</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{mitigationToDelete?.name}"? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDeleteMitigation} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
