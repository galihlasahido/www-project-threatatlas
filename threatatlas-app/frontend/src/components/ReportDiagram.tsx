import { ReactFlow, Background, BackgroundVariant, type Node, type Edge } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import DiagramNode from '@/components/DiagramNode';

const nodeTypes = {
  custom: DiagramNode,
};

interface ReportDiagramProps {
  nodes: Node[];
  edges: Edge[];
  height?: number;
}

export function ReportDiagram({ nodes, edges, height = 500 }: ReportDiagramProps) {
  if (!nodes || nodes.length === 0) return null;

  const readOnlyNodes = nodes.map(n => ({
    ...n,
    draggable: false,
    selectable: false,
    connectable: false,
    selected: false,
  }));

  // Force explicit inline styles on edges so html2canvas can see them
  const readOnlyEdges = edges.map(e => ({
    ...e,
    animated: false,
    selectable: false,
    style: {
      stroke: '#94a3b8',
      strokeWidth: 2,
    },
    labelStyle: {
      fill: '#475569',
      fontSize: 11,
      fontWeight: 500,
    },
    labelBgStyle: {
      fill: '#ffffff',
      stroke: '#cbd5e1',
      strokeWidth: 1,
    },
    labelBgPadding: [6, 4] as [number, number],
    labelBgBorderRadius: 4,
  }));

  return (
    <div style={{ width: '100%', height, background: '#ffffff' }} data-diagram-svg>
      {/*
        Force all ReactFlow SVG elements to use plain hex colors
        instead of CSS variables (which may use oklch).
        This ensures html2canvas-pro can render them correctly.
      */}
      <style>{`
        [data-diagram-svg] .react-flow__edge path.react-flow__edge-path {
          stroke: #94a3b8 !important;
          stroke-width: 2px !important;
          stroke-opacity: 1 !important;
          opacity: 1 !important;
        }
        [data-diagram-svg] .react-flow__edge path.react-flow__edge-interaction {
          stroke: transparent !important;
        }
        [data-diagram-svg] .react-flow__edge-text {
          fill: #475569 !important;
        }
        [data-diagram-svg] .react-flow__edge-textbg {
          fill: #ffffff !important;
          stroke: #cbd5e1 !important;
        }
        [data-diagram-svg] .react-flow__edge {
          opacity: 1 !important;
        }
        [data-diagram-svg] .react-flow__handle {
          opacity: 0 !important;
          width: 0 !important;
          height: 0 !important;
        }
        [data-diagram-svg] .react-flow__node {
          color: #1e293b !important;
        }
        [data-diagram-svg] .react-flow__renderer {
          background: #ffffff !important;
        }
        [data-diagram-svg] .react-flow__background pattern circle {
          fill: #cbd5e1 !important;
        }
      `}</style>
      <ReactFlow
        nodes={readOnlyNodes}
        edges={readOnlyEdges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        panOnDrag={false}
        zoomOnScroll={false}
        zoomOnPinch={false}
        zoomOnDoubleClick={false}
        preventScrolling={false}
        proOptions={{ hideAttribution: true }}
        defaultEdgeOptions={{
          style: { stroke: '#94a3b8', strokeWidth: 2 },
          type: 'default',
        }}
      >
        <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#cbd5e1" />
      </ReactFlow>
    </div>
  );
}
