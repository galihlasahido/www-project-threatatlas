import { useState, useRef } from 'react';
import { pentestFindingsApi } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent } from '@/components/ui/card';
import { Upload, FileText, Image, StickyNote, Trash2, Download, Loader2 } from 'lucide-react';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

interface EvidenceItem {
  id: number;
  finding_id: number;
  evidence_type: string; // 'file' | 'note'
  file_name?: string;
  file_type?: string;
  note_content?: string;
  created_at: string;
}

interface EvidenceSectionProps {
  findingId: number;
  evidence: EvidenceItem[];
  onRefresh: () => void;
}

export default function EvidenceSection({ findingId, evidence, onRefresh }: EvidenceSectionProps) {
  const [uploading, setUploading] = useState(false);
  const [noteText, setNoteText] = useState('');
  const [savingNote, setSavingNote] = useState(false);
  const [showNoteForm, setShowNoteForm] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 10 * 1024 * 1024) {
      alert('File size must be less than 10MB');
      return;
    }

    setUploading(true);
    try {
      await pentestFindingsApi.uploadEvidence(findingId, file);
      onRefresh();
    } catch (error) {
      console.error('Error uploading evidence:', error);
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleAddNote = async () => {
    if (!noteText.trim()) return;
    setSavingNote(true);
    try {
      await pentestFindingsApi.addNote(findingId, noteText.trim());
      setNoteText('');
      setShowNoteForm(false);
      onRefresh();
    } catch (error) {
      console.error('Error adding note:', error);
    } finally {
      setSavingNote(false);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Delete this evidence item?')) return;
    try {
      await pentestFindingsApi.deleteEvidence(id);
      onRefresh();
    } catch (error) {
      console.error('Error deleting evidence:', error);
    }
  };

  const getDownloadUrl = (id: number) => {
    const token = localStorage.getItem('token');
    return `${API_BASE_URL}/api/pentest-evidence/${id}/download?token=${token}`;
  };

  const isImage = (fileType?: string) => fileType?.startsWith('image/');
  const isPdf = (fileType?: string) => fileType === 'application/pdf';

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*,.pdf"
          className="hidden"
          onChange={handleFileUpload}
        />
        <Button
          variant="outline"
          size="sm"
          onClick={() => fileInputRef.current?.click()}
          disabled={uploading}
          className="h-8 rounded-lg"
        >
          {uploading ? (
            <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
          ) : (
            <Upload className="h-3.5 w-3.5 mr-1.5" />
          )}
          Upload File
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setShowNoteForm(!showNoteForm)}
          className="h-8 rounded-lg"
        >
          <StickyNote className="h-3.5 w-3.5 mr-1.5" />
          Add Note
        </Button>
      </div>

      {showNoteForm && (
        <div className="space-y-2 p-3 border rounded-lg bg-muted/30">
          <Textarea
            placeholder="Enter note..."
            value={noteText}
            onChange={(e) => setNoteText(e.target.value)}
            className="min-h-[80px] text-sm"
          />
          <div className="flex gap-2">
            <Button size="sm" onClick={handleAddNote} disabled={savingNote || !noteText.trim()} className="h-7">
              {savingNote ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : null}
              Save Note
            </Button>
            <Button size="sm" variant="ghost" onClick={() => { setShowNoteForm(false); setNoteText(''); }} className="h-7">
              Cancel
            </Button>
          </div>
        </div>
      )}

      {evidence.length === 0 ? (
        <p className="text-xs text-muted-foreground italic">No evidence attached yet.</p>
      ) : (
        <div className="space-y-2">
          {evidence.map((item) => (
            <Card key={item.id} className="border-border/60 rounded-lg">
              <CardContent className="p-3">
                <div className="flex items-start gap-3">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-muted shrink-0">
                    {item.evidence_type === 'note' ? (
                      <StickyNote className="h-4 w-4 text-amber-600" />
                    ) : isImage(item.file_type) ? (
                      <Image className="h-4 w-4 text-blue-600" />
                    ) : (
                      <FileText className="h-4 w-4 text-red-600" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    {item.evidence_type === 'note' ? (
                      <p className="text-sm text-foreground whitespace-pre-wrap">{item.note_content}</p>
                    ) : (
                      <div className="space-y-2">
                        <p className="text-sm font-medium truncate">{item.file_name}</p>
                        {isImage(item.file_type) && (
                          <img
                            src={getDownloadUrl(item.id)}
                            alt={item.file_name}
                            className="max-h-40 rounded-lg border"
                          />
                        )}
                        {isPdf(item.file_type) && (
                          <a
                            href={getDownloadUrl(item.id)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1.5 text-xs text-blue-600 hover:underline"
                          >
                            <Download className="h-3 w-3" />
                            Download PDF
                          </a>
                        )}
                      </div>
                    )}
                    <p className="text-xs text-muted-foreground mt-1">
                      {new Date(item.created_at).toLocaleString()}
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleDelete(item.id)}
                    className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive shrink-0"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
