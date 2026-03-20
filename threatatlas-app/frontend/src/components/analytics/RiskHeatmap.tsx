interface RiskHeatmapProps {
  data: Array<{ likelihood: number; impact: number; count: number }>;
}

function getCellColor(likelihood: number, impact: number): string {
  const score = likelihood * impact;
  if (score >= 20) return 'bg-red-500 text-white';
  if (score >= 15) return 'bg-red-400 text-white';
  if (score >= 12) return 'bg-orange-400 text-white';
  if (score >= 9) return 'bg-orange-300 text-orange-900';
  if (score >= 6) return 'bg-yellow-300 text-yellow-900';
  if (score >= 4) return 'bg-yellow-200 text-yellow-800';
  if (score >= 2) return 'bg-green-200 text-green-800';
  return 'bg-green-100 text-green-700';
}

export default function RiskHeatmap({ data }: RiskHeatmapProps) {
  const getCount = (likelihood: number, impact: number): number => {
    const cell = data.find((d) => d.likelihood === likelihood && d.impact === impact);
    return cell?.count ?? 0;
  };

  const rows = [5, 4, 3, 2, 1]; // top to bottom
  const cols = [1, 2, 3, 4, 5]; // left to right

  return (
    <div className="space-y-2">
      <div className="flex items-end gap-1">
        {/* Y-axis label */}
        <div className="w-16 flex flex-col items-center justify-center">
          <span className="text-xs font-semibold text-muted-foreground writing-mode-vertical rotate-180"
            style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)' }}>
            Likelihood
          </span>
        </div>

        <div className="flex-1">
          {/* Grid */}
          <div className="space-y-1">
            {rows.map((likelihood) => (
              <div key={likelihood} className="flex items-center gap-1">
                <div className="w-8 text-center text-xs font-medium text-muted-foreground">
                  {likelihood}
                </div>
                {cols.map((impact) => {
                  const count = getCount(likelihood, impact);
                  return (
                    <div
                      key={`${likelihood}-${impact}`}
                      className={`flex-1 h-14 flex items-center justify-center rounded-md text-sm font-bold transition-all ${getCellColor(likelihood, impact)} ${count > 0 ? 'ring-2 ring-offset-1 ring-foreground/20 shadow-md' : ''}`}
                      title={`Likelihood: ${likelihood}, Impact: ${impact}, Score: ${likelihood * impact}, Count: ${count}`}
                    >
                      {count > 0 ? count : ''}
                    </div>
                  );
                })}
              </div>
            ))}

            {/* X-axis numbers */}
            <div className="flex items-center gap-1">
              <div className="w-8" />
              {cols.map((impact) => (
                <div key={impact} className="flex-1 text-center text-xs font-medium text-muted-foreground">
                  {impact}
                </div>
              ))}
            </div>
          </div>

          {/* X-axis label */}
          <div className="text-center mt-1">
            <span className="text-xs font-semibold text-muted-foreground">Impact</span>
          </div>
        </div>
      </div>
    </div>
  );
}
