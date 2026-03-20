import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';

interface ChartCardProps {
  title: string;
  description?: string;
  children: React.ReactNode;
  loading?: boolean;
  className?: string;
}

export default function ChartCard({ title, description, children, loading, className }: ChartCardProps) {
  return (
    <Card className={cn('rounded-xl border-border/60 hover:shadow-lg transition-all duration-300', className)}>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-bold tracking-wide">{title}</CardTitle>
        {description && (
          <p className="text-xs text-muted-foreground">{description}</p>
        )}
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-[250px] w-full rounded-lg" />
          </div>
        ) : (
          children
        )}
      </CardContent>
    </Card>
  );
}
