import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import html2canvas from 'html2canvas-pro';

interface DiagramData {
  id: number;
  name: string;
  nodes: Array<{
    id: string;
    data: { label: string; type: string };
    position: { x: number; y: number };
    style?: { width?: number; height?: number };
  }>;
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
  diagrams: DiagramData[];
  threats: Array<{
    threat_name: string;
    category: string;
    element_id: string;
    risk_score: number | null;
    severity: string | null;
    status: string;
  }>;
  mitigations: Array<{
    mitigation_name: string;
    element_id: string;
    status: string;
    linked_threats: string[];
  }>;
  cves: Array<{
    cve_id: string;
    cvss_score: number | null;
    severity: string | null;
    description: string;
    technology: string;
  }>;
  cwes: Array<{
    cwe_id: string;
    name: string;
    threats: string[];
  }>;
}

const C = {
  primary: [37, 99, 235] as [number, number, number],
  critical: [220, 38, 38] as [number, number, number],
  high: [234, 88, 12] as [number, number, number],
  medium: [202, 138, 4] as [number, number, number],
  low: [22, 163, 74] as [number, number, number],
  mitigated: [22, 163, 74] as [number, number, number],
  identified: [37, 99, 235] as [number, number, number],
  accepted: [202, 138, 4] as [number, number, number],
  gray: [100, 116, 139] as [number, number, number],
  dark: [17, 24, 39] as [number, number, number],
  light: [107, 114, 128] as [number, number, number],
  headerBg: [241, 245, 249] as [number, number, number],
  // DFD node colors
  processFill: [219, 234, 254] as [number, number, number],
  processStroke: [59, 130, 246] as [number, number, number],
  processText: [30, 64, 175] as [number, number, number],
  datastoreFill: [254, 243, 199] as [number, number, number],
  datastoreStroke: [245, 158, 11] as [number, number, number],
  datastoreText: [146, 64, 14] as [number, number, number],
  externalFill: [252, 231, 243] as [number, number, number],
  externalStroke: [236, 72, 153] as [number, number, number],
  externalText: [157, 23, 77] as [number, number, number],
  boundaryFill: [248, 250, 252] as [number, number, number],
  boundaryStroke: [148, 163, 184] as [number, number, number],
  boundaryText: [71, 85, 105] as [number, number, number],
  edgeColor: [148, 163, 184] as [number, number, number],
  edgeLabelBg: [255, 255, 255] as [number, number, number],
  edgeLabelText: [100, 116, 139] as [number, number, number],
};

function sevColor(s: string | null): [number, number, number] {
  switch (s?.toLowerCase()) {
    case 'critical': return C.critical;
    case 'high': return C.high;
    case 'medium': return C.medium;
    case 'low': return C.low;
    default: return C.gray;
  }
}

function statusColor(s: string): [number, number, number] {
  switch (s?.toLowerCase()) {
    case 'mitigated': case 'verified': case 'implemented': return C.mitigated;
    case 'identified': return C.identified;
    case 'accepted': return C.accepted;
    default: return C.gray;
  }
}

function sectionHeader(pdf: jsPDF, title: string, y: number, margin: number): number {
  pdf.setFont('helvetica', 'bold');
  pdf.setFontSize(14);
  pdf.setTextColor(...C.dark);
  pdf.text(title, margin, y);
  y += 2;
  pdf.setFillColor(...C.primary);
  pdf.rect(margin, y, 30, 0.8, 'F');
  return y + 5;
}

/**
 * Draw a DFD diagram natively using jsPDF drawing primitives.
 * No html2canvas — fully vector, works perfectly in PDF.
 */
function drawDiagram(pdf: jsPDF, diagram: DiagramData, startY: number, margin: number, contentW: number, pageH: number): number {
  const nodes = diagram.nodes || [];
  const edges = diagram.edges || [];
  if (nodes.length === 0) return startY;

  // Compute bounds
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const n of nodes) {
    const w = n.style?.width || (n.data.type === 'boundary' ? 380 : 130);
    const h = n.style?.height || (n.data.type === 'boundary' ? 280 : 50);
    minX = Math.min(minX, n.position.x);
    minY = Math.min(minY, n.position.y);
    maxX = Math.max(maxX, n.position.x + w);
    maxY = Math.max(maxY, n.position.y + h);
  }

  const pad = 15;
  const srcW = maxX - minX + pad * 2;
  const srcH = maxY - minY + pad * 2;
  const scale = contentW / srcW;
  const diagramH = Math.min(srcH * scale, pageH - startY - margin - 15);
  const actualScale = diagramH / srcH;

  const ox = margin;
  const oy = startY;
  const tx = (x: number) => ox + (x - minX + pad) * actualScale;
  const ty = (y: number) => oy + (y - minY + pad) * actualScale;

  // Draw border around diagram area
  pdf.setDrawColor(226, 232, 240);
  pdf.setFillColor(255, 255, 255);
  pdf.roundedRect(ox - 2, oy - 2, contentW + 4, diagramH + 4, 2, 2, 'FD');

  // Dot grid
  pdf.setFillColor(226, 232, 240);
  const dotStep = 15 * actualScale;
  if (dotStep > 2) {
    for (let dx = ox; dx < ox + contentW; dx += dotStep) {
      for (let dy = oy; dy < oy + diagramH; dy += dotStep) {
        pdf.circle(dx, dy, 0.2, 'F');
      }
    }
  }

  // 1. Boundaries (background)
  const boundaries = nodes.filter(n => n.data.type === 'boundary');
  for (const n of boundaries) {
    const w = (n.style?.width || 380) * actualScale;
    const h = (n.style?.height || 280) * actualScale;
    const x = tx(n.position.x);
    const y = ty(n.position.y);
    pdf.setFillColor(...C.boundaryFill);
    pdf.setDrawColor(...C.boundaryStroke);
    pdf.setLineDashPattern([2, 1.5], 0);
    pdf.roundedRect(x, y, w, h, 2, 2, 'FD');
    pdf.setLineDashPattern([], 0);
    // Label
    pdf.setFontSize(6);
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(...C.boundaryText);
    pdf.text(n.data.label, x + 3, y + 4);
    // "Trust Boundary" bottom-right
    pdf.setFontSize(5);
    pdf.setFont('helvetica', 'italic');
    pdf.setTextColor(148, 163, 184);
    pdf.text('Trust Boundary', x + w - 3, y + h - 2, { align: 'right' });
  }

  // Build center map for edges
  const centers = new Map<string, { x: number; y: number }>();
  for (const n of nodes) {
    if (n.data.type === 'boundary') {
      const w = (n.style?.width || 380) * actualScale;
      const h = (n.style?.height || 280) * actualScale;
      centers.set(n.id, { x: tx(n.position.x) + w / 2, y: ty(n.position.y) + h / 2 });
    } else if (n.data.type === 'process') {
      const r = 10 * actualScale;
      centers.set(n.id, { x: tx(n.position.x) + r, y: ty(n.position.y) + r });
    } else {
      const w = 25 * actualScale;
      const h = 8 * actualScale;
      centers.set(n.id, { x: tx(n.position.x) + w / 2, y: ty(n.position.y) + h / 2 });
    }
  }

  // 2. Edges
  pdf.setLineDashPattern([], 0);
  for (const e of edges) {
    const src = centers.get(e.source);
    const tgt = centers.get(e.target);
    if (!src || !tgt) continue;

    pdf.setDrawColor(...C.edgeColor);
    pdf.setLineWidth(0.4);
    pdf.line(src.x, src.y, tgt.x, tgt.y);

    // Arrowhead
    const angle = Math.atan2(tgt.y - src.y, tgt.x - src.x);
    const arrowLen = 2;
    const ax = tgt.x - arrowLen * Math.cos(angle - 0.4);
    const ay = tgt.y - arrowLen * Math.sin(angle - 0.4);
    const bx = tgt.x - arrowLen * Math.cos(angle + 0.4);
    const by = tgt.y - arrowLen * Math.sin(angle + 0.4);
    pdf.setFillColor(...C.edgeColor);
    pdf.triangle(tgt.x, tgt.y, ax, ay, bx, by, 'F');

    // Label
    if (e.label) {
      const mx = (src.x + tgt.x) / 2;
      const my = (src.y + tgt.y) / 2;
      const labelW = pdf.getTextWidth(e.label) * 0.5 + 2;
      pdf.setFillColor(...C.edgeLabelBg);
      pdf.setDrawColor(226, 232, 240);
      pdf.roundedRect(mx - labelW, my - 1.8, labelW * 2, 3.6, 0.5, 0.5, 'FD');
      pdf.setFontSize(4.5);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor(...C.edgeLabelText);
      pdf.text(e.label, mx, my + 0.8, { align: 'center' });
    }
  }

  // 3. Process nodes (circles)
  const processes = nodes.filter(n => n.data.type === 'process');
  for (const n of processes) {
    const r = 10 * actualScale;
    const cx = tx(n.position.x) + r;
    const cy = ty(n.position.y) + r;
    pdf.setFillColor(...C.processFill);
    pdf.setDrawColor(...C.processStroke);
    pdf.setLineWidth(0.5);
    pdf.circle(cx, cy, r, 'FD');
    // Label
    pdf.setFontSize(Math.min(5, 4.5 * actualScale / 0.08));
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(...C.processText);
    const label = n.data.label.length > 18 ? n.data.label.slice(0, 18) + '..' : n.data.label;
    // Word wrap in circle
    const words = label.split(' ');
    const lines: string[] = [];
    let cur = '';
    for (const w of words) {
      const test = cur ? cur + ' ' + w : w;
      if (pdf.getTextWidth(test) > r * 1.6) {
        if (cur) lines.push(cur);
        cur = w;
      } else {
        cur = test;
      }
    }
    if (cur) lines.push(cur);
    const lineH = 2.2;
    const startTextY = cy - ((lines.length - 1) * lineH) / 2;
    for (let i = 0; i < lines.length; i++) {
      pdf.text(lines[i], cx, startTextY + i * lineH, { align: 'center' });
    }
  }

  // 4. Datastore nodes (parallel lines)
  const datastores = nodes.filter(n => n.data.type === 'datastore');
  for (const n of datastores) {
    const w = 25 * actualScale;
    const h = 8 * actualScale;
    const x = tx(n.position.x);
    const y = ty(n.position.y);
    pdf.setFillColor(...C.datastoreFill);
    pdf.setDrawColor(...C.datastoreStroke);
    pdf.setLineWidth(0.5);
    pdf.rect(x, y, w, h, 'F');
    // Top and bottom lines
    pdf.line(x, y, x + w, y);
    pdf.line(x, y + h, x + w, y + h);
    // Label
    pdf.setFontSize(Math.min(5, 4.5));
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(...C.datastoreText);
    const dlabel = n.data.label.length > 22 ? n.data.label.slice(0, 22) + '..' : n.data.label;
    pdf.text(dlabel, x + w / 2, y + h / 2 + 1, { align: 'center' });
  }

  // 5. External entity nodes (rectangles)
  const externals = nodes.filter(n => n.data.type === 'external');
  for (const n of externals) {
    const w = 25 * actualScale;
    const h = 8 * actualScale;
    const x = tx(n.position.x);
    const y = ty(n.position.y);
    pdf.setFillColor(...C.externalFill);
    pdf.setDrawColor(...C.externalStroke);
    pdf.setLineWidth(0.5);
    pdf.rect(x, y, w, h, 'FD');
    // Label
    pdf.setFontSize(Math.min(5, 4.5));
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(...C.externalText);
    const elabel = n.data.label.length > 22 ? n.data.label.slice(0, 22) + '..' : n.data.label;
    pdf.text(elabel, x + w / 2, y + h / 2 + 1, { align: 'center' });
  }

  // Legend
  const ly = oy + diagramH + 6;
  pdf.setFontSize(5);
  pdf.setFont('helvetica', 'normal');
  const legendItems = [
    { label: 'Process', fill: C.processFill, stroke: C.processStroke, shape: 'circle' },
    { label: 'Data Store', fill: C.datastoreFill, stroke: C.datastoreStroke, shape: 'rect' },
    { label: 'External Entity', fill: C.externalFill, stroke: C.externalStroke, shape: 'rect' },
    { label: 'Trust Boundary', fill: C.boundaryFill, stroke: C.boundaryStroke, shape: 'dash' },
    { label: 'Data Flow', fill: C.edgeColor, stroke: C.edgeColor, shape: 'line' },
  ];
  let lx = margin;
  for (const item of legendItems) {
    pdf.setFillColor(...item.fill);
    pdf.setDrawColor(...item.stroke);
    pdf.setLineWidth(0.3);
    if (item.shape === 'circle') {
      pdf.circle(lx + 1.5, ly, 1.5, 'FD');
    } else if (item.shape === 'dash') {
      pdf.setLineDashPattern([1, 0.5], 0);
      pdf.rect(lx, ly - 1.5, 3, 3, 'D');
      pdf.setLineDashPattern([], 0);
    } else if (item.shape === 'line') {
      pdf.setDrawColor(...item.stroke);
      pdf.line(lx, ly, lx + 4, ly);
      pdf.triangle(lx + 4, ly, lx + 3, ly - 0.5, lx + 3, ly + 0.5, 'F');
    } else {
      pdf.rect(lx, ly - 1.5, 3, 3, 'FD');
    }
    pdf.setTextColor(...C.dark);
    pdf.text(item.label, lx + 5, ly + 1);
    lx += pdf.getTextWidth(item.label) + 9;
  }

  return ly + 6;
}

export async function exportReportToPdf(_elementId: string, filename: string, reportData?: ReportData): Promise<void> {
  if (!reportData) return;

  const pdf = new jsPDF('p', 'mm', 'a4');
  const pageW = pdf.internal.pageSize.getWidth();
  const pageH = pdf.internal.pageSize.getHeight();
  const margin = 15;
  const contentW = pageW - margin * 2;
  let y = margin;

  // === COVER ===
  pdf.setFillColor(...C.primary);
  pdf.rect(0, 0, pageW, 4, 'F');
  y = 35;
  pdf.setFont('helvetica', 'bold');
  pdf.setFontSize(28);
  pdf.setTextColor(...C.dark);
  pdf.text('THREAT MODEL REPORT', margin, y);
  y += 4;
  pdf.setFillColor(...C.primary);
  pdf.rect(margin, y, 40, 1.5, 'F');

  y += 15;
  const dateStr = new Date(reportData.generated_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const meta = [
    ['Product:', reportData.product_name, C.dark],
    ['Generated:', dateStr, C.dark],
    ['Classification:', 'CONFIDENTIAL', C.critical],
  ];
  for (const [label, value, color] of meta) {
    pdf.setFontSize(10);
    pdf.setFont('helvetica', 'normal');
    pdf.setTextColor(...C.light);
    pdf.text(label as string, margin, y);
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(...(color as [number, number, number]));
    pdf.text(value as string, margin + 28, y);
    y += 7;
  }

  // === EXECUTIVE SUMMARY ===
  y += 8;
  y = sectionHeader(pdf, 'Executive Summary', y, margin);
  const s = reportData.summary;
  const boxW = (contentW - 9) / 4;
  const boxH = 22;
  const boxes = [
    { label: 'Total Threats', value: String(s.total_threats), sub: `${s.critical_count} Critical, ${s.high_count} High`, color: C.primary },
    { label: 'Mitigation Coverage', value: `${Math.round(s.mitigation_coverage)}%`, sub: '', color: s.mitigation_coverage >= 80 ? C.low : s.mitigation_coverage >= 50 ? C.medium : C.critical },
    { label: 'Risk Rating', value: s.overall_risk_rating, sub: '', color: sevColor(s.overall_risk_rating) },
    { label: 'Total CVEs', value: String(s.total_cves), sub: '', color: C.gray },
  ];
  boxes.forEach((box, i) => {
    const bx = margin + i * (boxW + 3);
    pdf.setDrawColor(226, 232, 240);
    pdf.setFillColor(255, 255, 255);
    pdf.roundedRect(bx, y, boxW, boxH, 2, 2, 'FD');
    pdf.setFontSize(16);
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(...box.color);
    pdf.text(box.value, bx + boxW / 2, y + 10, { align: 'center' });
    pdf.setFontSize(7);
    pdf.setFont('helvetica', 'normal');
    pdf.setTextColor(...C.light);
    pdf.text(box.label, bx + boxW / 2, y + 16, { align: 'center' });
    if (box.sub) { pdf.setFontSize(6); pdf.text(box.sub, bx + boxW / 2, y + 20, { align: 'center' }); }
  });
  y += boxH + 10;

  // === DATA FLOW DIAGRAMS (hybrid: html2canvas for nodes + native jsPDF for edges) ===
  const diagramEls = document.querySelectorAll('[data-diagram-svg]');
  for (let i = 0; i < diagramEls.length; i++) {
    const el = diagramEls[i] as HTMLElement;
    const diagram = reportData.diagrams[i];
    const diagramName = diagram?.name || `Diagram ${i + 1}`;

    if (y + 30 > pageH - margin) { pdf.addPage(); y = margin; }
    y = sectionHeader(pdf, 'Data Flow Diagram', y, margin);
    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(9);
    pdf.setTextColor(...C.light);
    pdf.text(diagramName, margin, y);
    y += 5;

    let imgPlaced = false;
    let imgY = y;
    let imgH = 0;

    try {
      // Step 1: Capture nodes/boundaries/background via html2canvas
      const canvas = await html2canvas(el, {
        scale: 2,
        backgroundColor: '#ffffff',
        logging: false,
        useCORS: true,
      });
      const imgData = canvas.toDataURL('image/jpeg', 0.85);
      const imgW = contentW;
      imgH = (canvas.height * imgW) / canvas.width;
      const maxH = pageH - y - margin - 10;
      const finalH = Math.min(imgH, maxH);
      const finalW = (finalH / imgH) * imgW;
      pdf.addImage(imgData, 'JPEG', margin, y, finalW, finalH);
      imgPlaced = true;
      imgH = finalH;
      imgY = y;
    } catch {
      // If capture fails, draw everything natively
      if (diagram) {
        y = drawDiagram(pdf, diagram, y, margin, contentW, pageH);
      }
      continue;
    }

    // Step 2: Draw edges on top of the captured image using native jsPDF
    if (imgPlaced && diagram?.nodes && diagram?.edges) {
      const nodes = diagram.nodes;
      const edges = diagram.edges;

      // Compute the same coordinate transform as ReactFlow's fitView
      let minX = Infinity, minY2 = Infinity, maxX = -Infinity, maxY = -Infinity;
      for (const n of nodes) {
        const nw = n.style?.width || (n.data.type === 'boundary' ? 380 : (n.data.type === 'process' ? 96 : 140));
        const nh = n.style?.height || (n.data.type === 'boundary' ? 280 : (n.data.type === 'process' ? 96 : 48));
        minX = Math.min(minX, n.position.x);
        minY2 = Math.min(minY2, n.position.y);
        maxX = Math.max(maxX, n.position.x + nw);
        maxY = Math.max(maxY, n.position.y + nh);
      }

      const srcW = maxX - minX;
      const srcH = maxY - minY2;
      // ReactFlow fitView with padding 0.15 on each side
      const padFrac = 0.15;
      const availW = contentW * (1 - padFrac * 2);
      const availH = imgH * (1 - padFrac * 2);
      const scaleX = availW / srcW;
      const scaleY = availH / srcH;
      const s = Math.min(scaleX, scaleY);
      const offsetX = margin + contentW * padFrac + (availW - srcW * s) / 2;
      const offsetY = imgY + imgH * padFrac + (availH - srcH * s) / 2;

      const tx = (x: number) => offsetX + (x - minX) * s;
      const ty = (yy: number) => offsetY + (yy - minY2) * s;

      // Build node centers
      const centers = new Map<string, { x: number; y: number }>();
      for (const n of nodes) {
        if (n.data.type === 'boundary') {
          const w = (n.style?.width || 380) * s;
          const h = (n.style?.height || 280) * s;
          centers.set(n.id, { x: tx(n.position.x) + w / 2, y: ty(n.position.y) + h / 2 });
        } else if (n.data.type === 'process') {
          const r = 48 * s;
          centers.set(n.id, { x: tx(n.position.x) + r, y: ty(n.position.y) + r });
        } else {
          const w = (n.data.type === 'datastore' ? 140 : 120) * s;
          const h = 48 * s;
          centers.set(n.id, { x: tx(n.position.x) + w / 2, y: ty(n.position.y) + h / 2 });
        }
      }

      // Draw edges
      for (const e of edges) {
        const src = centers.get(e.source);
        const tgt = centers.get(e.target);
        if (!src || !tgt) continue;

        // Line
        pdf.setDrawColor(148, 163, 184);
        pdf.setLineWidth(0.4);
        pdf.setLineDashPattern([], 0);
        pdf.line(src.x, src.y, tgt.x, tgt.y);

        // Arrowhead
        const angle = Math.atan2(tgt.y - src.y, tgt.x - src.x);
        const al = 2;
        pdf.setFillColor(148, 163, 184);
        pdf.triangle(
          tgt.x, tgt.y,
          tgt.x - al * Math.cos(angle - 0.4), tgt.y - al * Math.sin(angle - 0.4),
          tgt.x - al * Math.cos(angle + 0.4), tgt.y - al * Math.sin(angle + 0.4),
          'F'
        );

        // Label
        if (e.label) {
          const mx = (src.x + tgt.x) / 2;
          const my = (src.y + tgt.y) / 2;
          pdf.setFontSize(4.5);
          pdf.setFont('helvetica', 'normal');
          const tw = pdf.getTextWidth(String(e.label));
          pdf.setFillColor(255, 255, 255);
          pdf.setDrawColor(203, 213, 225);
          pdf.roundedRect(mx - tw / 2 - 2, my - 2, tw + 4, 4, 0.5, 0.5, 'FD');
          pdf.setTextColor(100, 116, 139);
          pdf.text(String(e.label), mx, my + 0.8, { align: 'center' });
        }
      }

      y = imgY + imgH + 8;
    }
  }
  // If no DOM elements found, fall back to fully native drawing
  if (diagramEls.length === 0) {
    for (const diagram of reportData.diagrams) {
      if (!diagram.nodes || diagram.nodes.length === 0) continue;
      if (y + 30 > pageH - margin) { pdf.addPage(); y = margin; }
      y = sectionHeader(pdf, 'Data Flow Diagram', y, margin);
      pdf.setFont('helvetica', 'normal');
      pdf.setFontSize(9);
      pdf.setTextColor(...C.light);
      pdf.text(diagram.name, margin, y);
      y += 5;
      y = drawDiagram(pdf, diagram, y, margin, contentW, pageH);
    }
  }

  // === THREAT SUMMARY ===
  if (reportData.threats.length > 0) {
    if (y + 20 > pageH - margin) { pdf.addPage(); y = margin; }
    y = sectionHeader(pdf, 'Threat Summary', y, margin);
    const sorted = [...reportData.threats].sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0));
    autoTable(pdf, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['#', 'Threat', 'Category', 'Element', 'Risk', 'Severity', 'Status']],
      body: sorted.map((t, i) => [String(i + 1), t.threat_name, t.category || '-', t.element_id, t.risk_score != null ? String(t.risk_score) : '-', t.severity || '-', t.status]),
      styles: { fontSize: 7, cellPadding: 2, lineColor: [226, 232, 240], lineWidth: 0.3 },
      headStyles: { fillColor: C.headerBg, textColor: C.dark, fontStyle: 'bold', fontSize: 7 },
      columnStyles: { 0: { cellWidth: 8, halign: 'center' }, 4: { cellWidth: 12, halign: 'center', fontStyle: 'bold' }, 5: { cellWidth: 16, halign: 'center' }, 6: { cellWidth: 18, halign: 'center' } },
      didParseCell: (data) => {
        if (data.section === 'body') {
          if (data.column.index === 5) { data.cell.styles.textColor = sevColor(String(data.cell.raw)); data.cell.styles.fontStyle = 'bold'; }
          if (data.column.index === 6) { data.cell.styles.textColor = statusColor(String(data.cell.raw)); data.cell.styles.fontStyle = 'bold'; }
        }
      },
    });
    y = (pdf as any).lastAutoTable.finalY + 8;
  }

  // === MITIGATION STATUS ===
  if (reportData.mitigations.length > 0) {
    if (y + 20 > pageH - margin) { pdf.addPage(); y = margin; }
    y = sectionHeader(pdf, 'Mitigation Status', y, margin);
    autoTable(pdf, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['#', 'Mitigation', 'Element', 'Status', 'Linked Threats']],
      body: reportData.mitigations.map((m, i) => [String(i + 1), m.mitigation_name, m.element_id, m.status, m.linked_threats?.length > 0 ? m.linked_threats.join(', ') : '-']),
      styles: { fontSize: 7, cellPadding: 2, lineColor: [226, 232, 240], lineWidth: 0.3 },
      headStyles: { fillColor: C.headerBg, textColor: C.dark, fontStyle: 'bold', fontSize: 7 },
      columnStyles: { 0: { cellWidth: 8, halign: 'center' }, 3: { cellWidth: 20, halign: 'center' } },
      didParseCell: (data) => { if (data.section === 'body' && data.column.index === 3) { data.cell.styles.textColor = statusColor(String(data.cell.raw)); data.cell.styles.fontStyle = 'bold'; } },
    });
    y = (pdf as any).lastAutoTable.finalY + 8;
  }

  // === CVE REPORT ===
  if (reportData.cves.length > 0) {
    if (y + 20 > pageH - margin) { pdf.addPage(); y = margin; }
    y = sectionHeader(pdf, 'CVE Report', y, margin);
    autoTable(pdf, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['CVE ID', 'CVSS', 'Severity', 'Technology', 'Description']],
      body: reportData.cves.map(c => [c.cve_id, c.cvss_score != null ? String(c.cvss_score) : '-', c.severity || '-', c.technology || '-', c.description ? (c.description.length > 80 ? c.description.slice(0, 80) + '...' : c.description) : '-']),
      styles: { fontSize: 7, cellPadding: 2, lineColor: [226, 232, 240], lineWidth: 0.3 },
      headStyles: { fillColor: C.headerBg, textColor: C.dark, fontStyle: 'bold', fontSize: 7 },
      columnStyles: { 1: { cellWidth: 12, halign: 'center', fontStyle: 'bold' }, 2: { cellWidth: 16, halign: 'center' } },
      didParseCell: (data) => { if (data.section === 'body' && data.column.index === 2) { data.cell.styles.textColor = sevColor(String(data.cell.raw)); data.cell.styles.fontStyle = 'bold'; } },
    });
    y = (pdf as any).lastAutoTable.finalY + 8;
  }

  // === COMPLIANCE MAPPING ===
  if (reportData.cwes.length > 0) {
    if (y + 20 > pageH - margin) { pdf.addPage(); y = margin; }
    y = sectionHeader(pdf, 'Compliance Mapping (CWE)', y, margin);
    autoTable(pdf, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['CWE ID', 'Name', 'Related Threats']],
      body: reportData.cwes.map(c => [c.cwe_id, c.name, c.threats?.length > 0 ? c.threats.join(', ') : '-']),
      styles: { fontSize: 7, cellPadding: 2, lineColor: [226, 232, 240], lineWidth: 0.3 },
      headStyles: { fillColor: C.headerBg, textColor: C.dark, fontStyle: 'bold', fontSize: 7 },
      columnStyles: { 0: { cellWidth: 20 } },
    });
  }

  // === FOOTER ===
  const totalPages = pdf.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    pdf.setPage(i);
    pdf.setFontSize(7);
    pdf.setFont('helvetica', 'normal');
    pdf.setTextColor(...C.light);
    pdf.text(`${reportData.product_name} — Threat Model Report`, margin, pageH - 8);
    pdf.text(`Page ${i} of ${totalPages}`, pageW - margin, pageH - 8, { align: 'right' });
    pdf.text(`Generated: ${dateStr}`, pageW / 2, pageH - 8, { align: 'center' });
    pdf.setDrawColor(226, 232, 240);
    pdf.line(margin, pageH - 12, pageW - margin, pageH - 12);
  }

  pdf.save(filename);
}
