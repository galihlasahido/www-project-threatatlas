import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

interface CWEBadgeProps {
  cweId: string;
  name: string;
  severity?: string;
  onClick?: () => void;
}

export function CWEBadge({ cweId, name, severity, onClick }: CWEBadgeProps) {
  const getSeverityClasses = () => {
    switch (severity?.toLowerCase()) {
      case 'high':
      case 'critical':
        return 'bg-red-100 text-red-800 border-red-300 hover:bg-red-200 dark:bg-red-900/40 dark:text-red-300 dark:border-red-700';
      case 'medium':
        return 'bg-orange-100 text-orange-800 border-orange-300 hover:bg-orange-200 dark:bg-orange-900/40 dark:text-orange-300 dark:border-orange-700';
      case 'low':
        return 'bg-blue-100 text-blue-800 border-blue-300 hover:bg-blue-200 dark:bg-blue-900/40 dark:text-blue-300 dark:border-blue-700';
      default:
        return 'bg-slate-100 text-slate-800 border-slate-300 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-600';
    }
  };

  return (
    <Badge
      variant="outline"
      className={cn(
        'text-xs cursor-pointer transition-colors',
        getSeverityClasses(),
        onClick && 'cursor-pointer'
      )}
      onClick={onClick}
    >
      <span className="font-semibold">{cweId}</span>
      <span className="mx-1 text-muted-foreground/60">|</span>
      <span className="truncate max-w-[150px]">{name}</span>
    </Badge>
  );
}
