import { useState, useEffect } from 'react';
import { technologyStacksApi, cvesApi } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Plus, Trash2, Search, Cpu, ShieldAlert } from 'lucide-react';
import { CVEList, type CVEItem } from '@/components/CVEList';

interface TechnologyStackEditorProps {
  diagramId: number;
  elementId: string;
  elementLabel: string;
}

interface TechStack {
  id: number;
  element_id: string;
  technology_name: string;
  version: string | null;
  vendor: string | null;
  cve_count?: number;
}

const COMMON_TECHNOLOGIES = [
  { name: 'PostgreSQL', vendor: 'postgresql' },
  { name: 'MySQL', vendor: 'oracle' },
  { name: 'Redis', vendor: 'redis' },
  { name: 'Nginx', vendor: 'f5' },
  { name: 'Apache', vendor: 'apache' },
  { name: 'Node.js', vendor: 'nodejs' },
  { name: 'Python', vendor: 'python' },
  { name: 'Java', vendor: 'oracle' },
  { name: 'Spring Boot', vendor: 'vmware' },
  { name: '.NET', vendor: 'microsoft' },
  { name: 'React', vendor: 'facebook' },
  { name: 'Docker', vendor: 'docker' },
  { name: 'Kubernetes', vendor: 'kubernetes' },
  { name: 'MongoDB', vendor: 'mongodb' },
  { name: 'RabbitMQ', vendor: 'vmware' },
  { name: 'Kafka', vendor: 'apache' },
  { name: 'Elasticsearch', vendor: 'elastic' },
  { name: 'Tomcat', vendor: 'apache' },
];

export function TechnologyStackEditor({ diagramId, elementId, elementLabel }: TechnologyStackEditorProps) {
  const [techStacks, setTechStacks] = useState<TechStack[]>([]);
  const [loading, setLoading] = useState(true);
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [techName, setTechName] = useState('');
  const [techVersion, setTechVersion] = useState('');
  const [techVendor, setTechVendor] = useState('');
  const [suggestions, setSuggestions] = useState<typeof COMMON_TECHNOLOGIES>([]);
  const [saving, setSaving] = useState(false);

  // CVE scanning state
  const [scanningId, setScanningId] = useState<number | null>(null);
  const [cveDialogOpen, setCveDialogOpen] = useState(false);
  const [cveResults, setCveResults] = useState<CVEItem[]>([]);
  const [cveLoading, setCveLoading] = useState(false);
  const [cveTechName, setCveTechName] = useState('');

  useEffect(() => {
    loadTechStacks();
  }, [diagramId, elementId]);

  const loadTechStacks = async () => {
    try {
      setLoading(true);
      const response = await technologyStacksApi.listForElement(diagramId, elementId);
      const stacks: TechStack[] = response.data;

      // Fetch CVE counts for each tech stack
      const stacksWithCounts = await Promise.all(
        stacks.map(async (stack) => {
          try {
            const cveRes = await technologyStacksApi.getCVEs(stack.id);
            return { ...stack, cve_count: Array.isArray(cveRes.data) ? cveRes.data.length : 0 };
          } catch {
            return { ...stack, cve_count: 0 };
          }
        })
      );

      setTechStacks(stacksWithCounts);
    } catch (error) {
      console.error('Error loading technology stacks:', error);
      setTechStacks([]);
    } finally {
      setLoading(false);
    }
  };

  const handleTechNameChange = (value: string) => {
    setTechName(value);
    if (value.length > 0) {
      const filtered = COMMON_TECHNOLOGIES.filter((t) =>
        t.name.toLowerCase().includes(value.toLowerCase())
      );
      setSuggestions(filtered);
    } else {
      setSuggestions([]);
    }
  };

  const handleSelectSuggestion = (tech: (typeof COMMON_TECHNOLOGIES)[0]) => {
    setTechName(tech.name);
    setTechVendor(tech.vendor);
    setSuggestions([]);
  };

  const handleAddTechnology = async () => {
    if (!techName.trim()) return;

    try {
      setSaving(true);
      await technologyStacksApi.create(diagramId, {
        element_id: elementId,
        technology_name: techName.trim(),
        version: techVersion.trim() || undefined,
        vendor: techVendor.trim() || undefined,
      });
      setAddDialogOpen(false);
      setTechName('');
      setTechVersion('');
      setTechVendor('');
      setSuggestions([]);
      await loadTechStacks();
    } catch (error) {
      console.error('Error adding technology:', error);
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteTech = async (id: number) => {
    try {
      await technologyStacksApi.delete(id);
      await loadTechStacks();
    } catch (error) {
      console.error('Error deleting technology:', error);
    }
  };

  const handleScanCVEs = async (tech: TechStack) => {
    setScanningId(tech.id);
    setCveTechName(tech.technology_name);
    setCveLoading(true);
    setCveDialogOpen(true);
    setCveResults([]);

    try {
      const response = await cvesApi.search({
        product: tech.technology_name.toLowerCase(),
        vendor: tech.vendor || undefined,
        version: tech.version || undefined,
        fetch_from_nvd: true,
      });
      setCveResults(Array.isArray(response.data) ? response.data : response.data?.results || []);
    } catch (error) {
      console.error('Error scanning CVEs:', error);
      setCveResults([]);
    } finally {
      setCveLoading(false);
      setScanningId(null);
    }
  };

  if (loading) {
    return (
      <div className="text-sm text-muted-foreground p-3 text-center">
        Loading technologies...
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Cpu className="h-4 w-4 text-muted-foreground" />
          <span className="text-xs font-medium text-muted-foreground">
            {techStacks.length} {techStacks.length === 1 ? 'technology' : 'technologies'}
          </span>
        </div>
        <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => setAddDialogOpen(true)}>
          <Plus className="h-3 w-3 mr-1" />
          Add Technology
        </Button>
      </div>

      {techStacks.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="p-4 text-center">
            <Cpu className="h-6 w-6 text-muted-foreground mx-auto mb-2" />
            <p className="text-xs text-muted-foreground">
              No technologies added yet. Add technologies to scan for CVEs.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {techStacks.map((tech) => (
            <div
              key={tech.id}
              className="flex items-center gap-2 p-2.5 rounded-lg border bg-card hover:bg-muted/30 transition-colors group"
            >
              <div className="flex-1 min-w-0 flex items-center gap-2 flex-wrap">
                <Badge variant="secondary" className="text-xs font-semibold">
                  {tech.technology_name}
                </Badge>
                {tech.version && (
                  <Badge variant="outline" className="text-xs">
                    v{tech.version}
                  </Badge>
                )}
                {tech.vendor && (
                  <span className="text-xs text-muted-foreground">{tech.vendor}</span>
                )}
                {tech.cve_count !== undefined && tech.cve_count > 0 && (
                  <Badge variant="outline" className="text-xs bg-red-50 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-400 dark:border-red-800">
                    <ShieldAlert className="h-3 w-3 mr-1" />
                    {tech.cve_count} CVE{tech.cve_count !== 1 ? 's' : ''}
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-1 shrink-0">
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-7 text-xs px-2"
                  onClick={() => handleScanCVEs(tech)}
                  disabled={scanningId === tech.id}
                >
                  <Search className="h-3 w-3 mr-1" />
                  {scanningId === tech.id ? 'Scanning...' : 'Scan CVEs'}
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  className="h-7 w-7 opacity-0 group-hover:opacity-100 transition-opacity"
                  onClick={() => handleDeleteTech(tech.id)}
                >
                  <Trash2 className="h-3 w-3 text-destructive" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Add Technology Dialog */}
      <Dialog open={addDialogOpen} onOpenChange={setAddDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Add Technology</DialogTitle>
            <DialogDescription>
              Add a technology to "{elementLabel}" to track known vulnerabilities.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-3">
            <div className="grid gap-2">
              <Label htmlFor="tech-name">Technology Name</Label>
              <div className="relative">
                <Input
                  id="tech-name"
                  value={techName}
                  onChange={(e) => handleTechNameChange(e.target.value)}
                  placeholder="e.g., PostgreSQL, Nginx, Node.js"
                  autoComplete="off"
                />
                {suggestions.length > 0 && (
                  <div className="absolute z-50 top-full left-0 right-0 mt-1 bg-popover border rounded-lg shadow-lg max-h-40 overflow-auto">
                    {suggestions.map((s) => (
                      <button
                        key={s.name}
                        className="w-full text-left px-3 py-2 text-sm hover:bg-muted transition-colors flex items-center justify-between"
                        onClick={() => handleSelectSuggestion(s)}
                      >
                        <span className="font-medium">{s.name}</span>
                        <span className="text-xs text-muted-foreground">{s.vendor}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="tech-version">Version (optional)</Label>
              <Input
                id="tech-version"
                value={techVersion}
                onChange={(e) => setTechVersion(e.target.value)}
                placeholder="e.g., 15.4, 1.24, 20.10"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="tech-vendor">Vendor (optional)</Label>
              <Input
                id="tech-vendor"
                value={techVendor}
                onChange={(e) => setTechVendor(e.target.value)}
                placeholder="e.g., postgresql, nginx, nodejs"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleAddTechnology} disabled={!techName.trim() || saving}>
              {saving ? 'Adding...' : 'Add Technology'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* CVE Scan Results Dialog */}
      <Dialog open={cveDialogOpen} onOpenChange={setCveDialogOpen}>
        <DialogContent className="!max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>CVE Scan Results - {cveTechName}</DialogTitle>
            <DialogDescription>
              Known vulnerabilities found for this technology from NVD.
            </DialogDescription>
          </DialogHeader>
          <CVEList cves={cveResults} loading={cveLoading} />
          <DialogFooter>
            <Button variant="outline" onClick={() => setCveDialogOpen(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
