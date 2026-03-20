import { useState } from 'react';
import { pentestFindingsApi } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Plus, Trash2, Loader2, CheckCircle2, XCircle, AlertCircle } from 'lucide-react';

interface Retest {
  id: number;
  finding_id: number;
  tester_name: string;
  result: string; // 'pass' | 'fail' | 'partial'
  notes?: string;
  tested_at: string;
  created_at: string;
}

interface RetestTimelineProps {
  findingId: number;
  retests: Retest[];
  onRefresh: () => void;
}

const resultConfig: Record<string, { label: string; color: string; bgColor: string; icon: typeof CheckCircle2 }> = {
  pass: { label: 'Pass', color: 'text-green-700', bgColor: 'bg-green-100 border-green-300', icon: CheckCircle2 },
  fail: { label: 'Fail', color: 'text-red-700', bgColor: 'bg-red-100 border-red-300', icon: XCircle },
  partial: { label: 'Partial', color: 'text-amber-700', bgColor: 'bg-amber-100 border-amber-300', icon: AlertCircle },
};

export default function RetestTimeline({ findingId, retests, onRefresh }: RetestTimelineProps) {
  const [showForm, setShowForm] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formData, setFormData] = useState({
    tester_name: '',
    result: 'pass',
    notes: '',
    tested_at: new Date().toISOString().split('T')[0],
  });

  const handleSubmit = async () => {
    if (!formData.tester_name.trim()) return;
    setSubmitting(true);
    try {
      await pentestFindingsApi.createRetest(findingId, {
        ...formData,
        tested_at: new Date(formData.tested_at).toISOString(),
      });
      setFormData({ tester_name: '', result: 'pass', notes: '', tested_at: new Date().toISOString().split('T')[0] });
      setShowForm(false);
      onRefresh();
    } catch (error) {
      console.error('Error creating retest:', error);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (retestId: number) => {
    if (!confirm('Delete this retest entry?')) return;
    try {
      await pentestFindingsApi.deleteRetest(findingId, retestId);
      onRefresh();
    } catch (error) {
      console.error('Error deleting retest:', error);
    }
  };

  const sortedRetests = [...retests].sort((a, b) => new Date(b.tested_at).getTime() - new Date(a.tested_at).getTime());

  return (
    <div className="space-y-3">
      <Button
        variant="outline"
        size="sm"
        onClick={() => setShowForm(!showForm)}
        className="h-8 rounded-lg"
      >
        <Plus className="h-3.5 w-3.5 mr-1.5" />
        Add Retest
      </Button>

      {showForm && (
        <div className="space-y-3 p-3 border rounded-lg bg-muted/30">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Tester Name</label>
              <Input
                value={formData.tester_name}
                onChange={(e) => setFormData({ ...formData, tester_name: e.target.value })}
                placeholder="Tester name"
                className="h-8 text-sm"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Result</label>
              <Select value={formData.result} onValueChange={(v) => setFormData({ ...formData, result: v })}>
                <SelectTrigger className="h-8 text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="pass">Pass</SelectItem>
                  <SelectItem value="fail">Fail</SelectItem>
                  <SelectItem value="partial">Partial</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1 block">Tested At</label>
            <Input
              type="date"
              value={formData.tested_at}
              onChange={(e) => setFormData({ ...formData, tested_at: e.target.value })}
              className="h-8 text-sm w-48"
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1 block">Notes</label>
            <Textarea
              value={formData.notes}
              onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
              placeholder="Retest notes..."
              className="min-h-[60px] text-sm"
            />
          </div>
          <div className="flex gap-2">
            <Button size="sm" onClick={handleSubmit} disabled={submitting || !formData.tester_name.trim()} className="h-7">
              {submitting ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : null}
              Save
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setShowForm(false)} className="h-7">Cancel</Button>
          </div>
        </div>
      )}

      {sortedRetests.length === 0 ? (
        <p className="text-xs text-muted-foreground italic">No retest history yet.</p>
      ) : (
        <div className="relative ml-3">
          {/* Vertical timeline line */}
          <div className="absolute left-0 top-0 bottom-0 w-0.5 bg-border" />

          <div className="space-y-4">
            {sortedRetests.map((retest) => {
              const config = resultConfig[retest.result] || resultConfig.fail;
              const Icon = config.icon;

              return (
                <div key={retest.id} className="relative pl-6">
                  {/* Timeline dot */}
                  <div className="absolute left-0 top-1 -translate-x-1/2 flex h-5 w-5 items-center justify-center rounded-full bg-background border-2 border-border">
                    <Icon className={`h-3 w-3 ${config.color}`} />
                  </div>

                  <div className="flex items-start justify-between gap-2">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={`text-xs border ${config.bgColor} ${config.color}`}>
                          {config.label}
                        </Badge>
                        <span className="text-xs font-medium">{retest.tester_name}</span>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        {new Date(retest.tested_at).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}
                      </p>
                      {retest.notes && (
                        <p className="text-xs text-muted-foreground bg-muted/50 p-2 rounded-lg mt-1">{retest.notes}</p>
                      )}
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDelete(retest.id)}
                      className="h-6 w-6 p-0 text-muted-foreground hover:text-destructive shrink-0"
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
