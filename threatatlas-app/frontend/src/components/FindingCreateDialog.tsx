import { useState, useRef } from 'react';
import { pentestFindingsApi } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Loader2, Upload, X, FileText, Image as ImageIcon } from 'lucide-react';

// Predefined categories aligned with OWASP/CWE taxonomy for consistent analytics
const FINDING_CATEGORIES = [
  'Injection',
  'Broken Authentication',
  'Sensitive Data Exposure',
  'XML External Entity (XXE)',
  'Broken Access Control',
  'Security Misconfiguration',
  'Cross-Site Scripting (XSS)',
  'Insecure Deserialization',
  'Using Components with Known Vulnerabilities',
  'Insufficient Logging & Monitoring',
  'Server-Side Request Forgery (SSRF)',
  'Cryptographic Failures',
  'Business Logic',
  'Denial of Service',
  'Information Disclosure',
  'Privilege Escalation',
  'File Upload',
  'Remote Code Execution',
  'Other',
];

interface FindingCreateDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  pentestId: number;
  onSuccess: () => void;
}

interface PendingFile {
  file: File;
  preview?: string;
}

export default function FindingCreateDialog({ open, onOpenChange, pentestId, onSuccess }: FindingCreateDialogProps) {
  const [submitting, setSubmitting] = useState(false);
  const [files, setFiles] = useState<PendingFile[]>([]);
  const [categorySearch, setCategorySearch] = useState('');
  const [showCategoryDropdown, setShowCategoryDropdown] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [formData, setFormData] = useState({
    title: '',
    severity: 'medium',
    category: '',
    affected_element: '',
    description: '',
    steps_to_reproduce: '',
    recommendation: '',
    likelihood: '',
    cvss_score: '',
    remediation_priority: '',
    due_date: '',
    assigned_to: '',
  });

  const resetForm = () => {
    setFormData({
      title: '',
      severity: 'medium',
      category: '',
      affected_element: '',
      description: '',
      steps_to_reproduce: '',
      recommendation: '',
      likelihood: '',
      cvss_score: '',
      remediation_priority: '',
      due_date: '',
      assigned_to: '',
    });
    setFiles([]);
    setCategorySearch('');
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = Array.from(e.target.files || []);
    const validFiles = selected.filter(f => {
      if (f.size > 10 * 1024 * 1024) {
        alert(`${f.name} exceeds 10MB limit`);
        return false;
      }
      const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'application/pdf'];
      if (!allowed.includes(f.type)) {
        alert(`${f.name}: only images and PDFs are allowed`);
        return false;
      }
      return true;
    });

    const newFiles: PendingFile[] = validFiles.map(file => ({
      file,
      preview: file.type.startsWith('image/') ? URL.createObjectURL(file) : undefined,
    }));
    setFiles(prev => [...prev, ...newFiles]);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const removeFile = (idx: number) => {
    setFiles(prev => {
      const removed = prev[idx];
      if (removed.preview) URL.revokeObjectURL(removed.preview);
      return prev.filter((_, i) => i !== idx);
    });
  };

  const filteredCategories = FINDING_CATEGORIES.filter(c =>
    c.toLowerCase().includes(categorySearch.toLowerCase())
  );

  const handleCategorySelect = (cat: string) => {
    setFormData({ ...formData, category: cat });
    setCategorySearch(cat);
    setShowCategoryDropdown(false);
  };

  const handleCategoryInput = (value: string) => {
    setCategorySearch(value);
    setFormData({ ...formData, category: value });
    setShowCategoryDropdown(value.length > 0);
  };

  const handleSubmit = async () => {
    if (!formData.title.trim()) return;
    setSubmitting(true);
    try {
      // Create the finding
      const payload: any = {
        ...formData,
        pentest_id: pentestId,
        status: 'open',
      };
      if (payload.likelihood) payload.likelihood = Number(payload.likelihood);
      else delete payload.likelihood;
      if (payload.cvss_score) payload.cvss_score = Number(payload.cvss_score);
      else delete payload.cvss_score;
      if (!payload.remediation_priority) delete payload.remediation_priority;
      if (!payload.due_date) delete payload.due_date;
      else payload.due_date = new Date(payload.due_date).toISOString();
      if (!payload.assigned_to) delete payload.assigned_to;
      const res = await pentestFindingsApi.create(payload);
      const findingId = res.data.id;

      // Upload all files as evidence
      for (const { file } of files) {
        try {
          await pentestFindingsApi.uploadEvidence(findingId, file);
        } catch (err) {
          console.error(`Failed to upload ${file.name}:`, err);
        }
      }

      // Cleanup previews
      files.forEach(f => { if (f.preview) URL.revokeObjectURL(f.preview); });

      resetForm();
      onSuccess();
      onOpenChange(false);
    } catch (error) {
      console.error('Error creating finding:', error);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(v) => { onOpenChange(v); if (!v) resetForm(); }}>
      <DialogContent className="sm:max-w-[600px] max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Add Finding</DialogTitle>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <div className="space-y-2">
            <Label>Title *</Label>
            <Input
              value={formData.title}
              onChange={(e) => setFormData({ ...formData, title: e.target.value })}
              placeholder="Finding title"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Severity *</Label>
              <Select value={formData.severity} onValueChange={(v) => setFormData({ ...formData, severity: v })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">
                    <span className="flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-red-500" /> Critical</span>
                  </SelectItem>
                  <SelectItem value="high">
                    <span className="flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-orange-500" /> High</span>
                  </SelectItem>
                  <SelectItem value="medium">
                    <span className="flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-yellow-500" /> Medium</span>
                  </SelectItem>
                  <SelectItem value="low">
                    <span className="flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-green-500" /> Low</span>
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Category *</Label>
              <div className="relative">
                <Input
                  value={categorySearch}
                  onChange={(e) => handleCategoryInput(e.target.value)}
                  onFocus={() => setShowCategoryDropdown(true)}
                  onBlur={() => setTimeout(() => setShowCategoryDropdown(false), 200)}
                  placeholder="Select or type category..."
                  autoComplete="off"
                />
                {showCategoryDropdown && filteredCategories.length > 0 && (
                  <div className="absolute z-50 top-full left-0 right-0 mt-1 bg-popover border rounded-lg shadow-lg max-h-48 overflow-auto">
                    {filteredCategories.map(cat => (
                      <button
                        key={cat}
                        type="button"
                        className="w-full text-left px-3 py-2 text-sm hover:bg-muted transition-colors"
                        onMouseDown={(e) => { e.preventDefault(); handleCategorySelect(cat); }}
                      >
                        {cat}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div className="space-y-2">
              <Label>Likelihood (1-5)</Label>
              <Select value={formData.likelihood} onValueChange={(v) => setFormData({ ...formData, likelihood: v })}>
                <SelectTrigger>
                  <SelectValue placeholder="Select..." />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">1 - Rare</SelectItem>
                  <SelectItem value="2">2 - Unlikely</SelectItem>
                  <SelectItem value="3">3 - Possible</SelectItem>
                  <SelectItem value="4">4 - Likely</SelectItem>
                  <SelectItem value="5">5 - Almost Certain</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>CVSS Score (0-10)</Label>
              <Input
                type="number"
                min="0"
                max="10"
                step="0.1"
                value={formData.cvss_score}
                onChange={(e) => setFormData({ ...formData, cvss_score: e.target.value })}
                placeholder="e.g. 7.5"
              />
            </div>
            <div className="space-y-2">
              <Label>Remediation Priority</Label>
              <Select value={formData.remediation_priority} onValueChange={(v) => setFormData({ ...formData, remediation_priority: v })}>
                <SelectTrigger>
                  <SelectValue placeholder="Select..." />
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

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Due Date</Label>
              <Input
                type="date"
                value={formData.due_date}
                onChange={(e) => setFormData({ ...formData, due_date: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label>Assigned To</Label>
              <Input
                value={formData.assigned_to}
                onChange={(e) => setFormData({ ...formData, assigned_to: e.target.value })}
                placeholder="Who will fix this?"
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label>Affected Element</Label>
            <Input
              value={formData.affected_element}
              onChange={(e) => setFormData({ ...formData, affected_element: e.target.value })}
              placeholder="e.g. /api/users endpoint, login page"
            />
          </div>

          <div className="space-y-2">
            <Label>Description</Label>
            <Textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="Describe the vulnerability..."
              className="min-h-[80px]"
            />
          </div>

          <div className="space-y-2">
            <Label>Steps to Reproduce</Label>
            <Textarea
              value={formData.steps_to_reproduce}
              onChange={(e) => setFormData({ ...formData, steps_to_reproduce: e.target.value })}
              placeholder="1. Navigate to...&#10;2. Enter...&#10;3. Observe..."
              className="min-h-[80px]"
            />
          </div>

          <div className="space-y-2">
            <Label>Recommendation</Label>
            <Textarea
              value={formData.recommendation}
              onChange={(e) => setFormData({ ...formData, recommendation: e.target.value })}
              placeholder="Recommended fix or mitigation..."
              className="min-h-[60px]"
            />
          </div>

          {/* Evidence Upload */}
          <div className="space-y-2">
            <Label>Evidence (optional)</Label>
            <div
              className="border-2 border-dashed rounded-lg p-4 text-center cursor-pointer hover:border-primary/50 hover:bg-muted/30 transition-colors"
              onClick={() => fileInputRef.current?.click()}
            >
              <Upload className="h-6 w-6 mx-auto mb-2 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">Click to upload images or PDFs</p>
              <p className="text-xs text-muted-foreground mt-1">Max 10MB per file</p>
              <input
                ref={fileInputRef}
                type="file"
                multiple
                accept="image/*,.pdf"
                onChange={handleFileSelect}
                className="hidden"
              />
            </div>

            {files.length > 0 && (
              <div className="space-y-2 mt-2">
                {files.map((f, idx) => (
                  <div key={idx} className="flex items-center gap-3 p-2 border rounded-lg bg-muted/20">
                    {f.preview ? (
                      <img src={f.preview} alt="" className="w-10 h-10 rounded object-cover" />
                    ) : (
                      <div className="w-10 h-10 rounded bg-red-50 flex items-center justify-center">
                        <FileText className="h-5 w-5 text-red-500" />
                      </div>
                    )}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{f.file.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {(f.file.size / 1024).toFixed(0)} KB
                        <Badge variant="outline" className="ml-2 text-xs">
                          {f.file.type.startsWith('image/') ? 'Image' : 'PDF'}
                        </Badge>
                      </p>
                    </div>
                    <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => removeFile(idx)}>
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={handleSubmit} disabled={submitting || !formData.title.trim()}>
            {submitting && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            {submitting ? (files.length > 0 ? 'Creating & Uploading...' : 'Creating...') : `Create Finding${files.length > 0 ? ` (${files.length} file${files.length > 1 ? 's' : ''})` : ''}`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
