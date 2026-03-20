import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const api = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add request interceptor to include auth token and ensure trailing slashes
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }

  // Add trailing slash to URL if not present (prevents 307 redirects from FastAPI)
  // Skip for DELETE/PUT/PATCH — browsers may not preserve method on 307 redirects
  const method = (config.method || 'get').toLowerCase();
  if (method === 'get' || method === 'post') {
    if (config.url && !config.url.endsWith('/') && !config.url.includes('?')) {
      config.url = `${config.url}/`;
    } else if (config.url && !config.url.endsWith('/') && config.url.includes('?')) {
      // Handle URLs with query parameters
      const [path, query] = config.url.split('?');
      if (!path.endsWith('/')) {
        config.url = `${path}/?${query}`;
      }
    }
  }

  return config;
});

// Add response interceptor to handle 401 errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Product API
export const productsApi = {
  list: () => api.get('/products'),
  get: (id: number) => api.get(`/products/${id}`),
  create: (data: { name: string; description?: string }) => api.post('/products', data),
  update: (id: number, data: { name?: string; description?: string }) => api.put(`/products/${id}`, data),
  delete: (id: number) => api.delete(`/products/${id}`),
};

// Framework API
export const frameworksApi = {
  list: () => api.get('/frameworks'),
  get: (id: number) => api.get(`/frameworks/${id}`),
  create: (data: { name: string; description?: string }) => api.post('/frameworks', data),
  update: (id: number, data: { name?: string; description?: string }) => api.put(`/frameworks/${id}`, data),
  delete: (id: number) => api.delete(`/frameworks/${id}`),
};

// Threat API
export const threatsApi = {
  list: (params?: { framework_id?: number; is_custom?: boolean }) => api.get('/threats', { params }),
  get: (id: number) => api.get(`/threats/${id}`),
  create: (data: { framework_id: number; name: string; description?: string; category?: string; is_custom?: boolean }) => api.post('/threats', data),
  update: (id: number, data: { name?: string; description?: string; category?: string }) => api.put(`/threats/${id}`, data),
  delete: (id: number) => api.delete(`/threats/${id}`),
};

// Mitigation API
export const mitigationsApi = {
  list: (params?: { framework_id?: number; is_custom?: boolean }) => api.get('/mitigations', { params }),
  get: (id: number) => api.get(`/mitigations/${id}`),
  create: (data: { framework_id: number; name: string; description?: string; category?: string; is_custom?: boolean }) => api.post('/mitigations', data),
  update: (id: number, data: { name?: string; description?: string; category?: string }) => api.put(`/mitigations/${id}`, data),
  delete: (id: number) => api.delete(`/mitigations/${id}`),
};

// Diagram API
export const diagramsApi = {
  list: (params?: { product_id?: number }) => api.get('/diagrams', { params }),
  get: (id: number) => api.get(`/diagrams/${id}`),
  create: (data: { product_id: number; name: string; description?: string; diagram_data?: any }) => api.post('/diagrams', data),
  update: (id: number, data: { name?: string; description?: string; diagram_data?: any; auto_version?: boolean; version_comment?: string }) => api.put(`/diagrams/${id}`, data),
  delete: (id: number) => api.delete(`/diagrams/${id}`),
};

// DiagramVersion API
export const diagramVersionsApi = {
  list: (diagramId: number) => api.get(`/diagram-versions/${diagramId}/versions`),
  get: (diagramId: number, versionNumber: number) => api.get(`/diagram-versions/${diagramId}/versions/${versionNumber}`),
  create: (diagramId: number, data: { comment?: string }) => api.post(`/diagram-versions/${diagramId}/versions`, data),
  restore: (diagramId: number, versionNumber: number) => api.post(`/diagram-versions/${diagramId}/versions/${versionNumber}/restore`),
  compare: (diagramId: number, fromVersion: number, toVersion: number) => api.get(`/diagram-versions/${diagramId}/versions/compare`, { params: { from_version: fromVersion, to_version: toVersion } }),
  delete: (diagramId: number, versionNumber: number) => api.delete(`/diagram-versions/${diagramId}/versions/${versionNumber}`),
};

// Model API
export const modelsApi = {
  list: () => api.get('/models'),
  get: (id: number) => api.get(`/models/${id}`),
  listByDiagram: (diagramId: number) => api.get(`/models/diagram/${diagramId}`),
  create: (data: { diagram_id: number; framework_id: number; name: string; description?: string }) => api.post('/models', data),
  update: (id: number, data: { name?: string; description?: string; status?: string; completed_at?: string }) => api.put(`/models/${id}`, data),
  delete: (id: number) => api.delete(`/models/${id}`),
};

// DiagramThreat API
export const diagramThreatsApi = {
  list: (params?: { diagram_id?: number; model_id?: number; element_id?: string }) => api.get('/diagram-threats', { params }),
  get: (id: number) => api.get(`/diagram-threats/${id}`),
  create: (data: { diagram_id: number; model_id: number; threat_id: number; element_id: string; element_type: string; status?: string; notes?: string; likelihood?: number | null; impact?: number | null }) => api.post('/diagram-threats', data),
  update: (id: number, data: { status?: string; notes?: string; likelihood?: number | null; impact?: number | null }) => api.put(`/diagram-threats/${id}`, data),
  delete: (id: number) => api.delete(`/diagram-threats/${id}`),
};

// DiagramMitigation API
export const diagramMitigationsApi = {
  list: (params?: { diagram_id?: number; model_id?: number; element_id?: string }) => api.get('/diagram-mitigations', { params }),
  get: (id: number) => api.get(`/diagram-mitigations/${id}`),
  create: (data: { diagram_id: number; model_id: number; mitigation_id: number; element_id: string; element_type: string; threat_id?: number | null; status?: string; notes?: string | null }) => api.post('/diagram-mitigations', data),
  update: (id: number, data: { status?: string; notes?: string | null }) => api.put(`/diagram-mitigations/${id}`, data),
  delete: (id: number) => api.delete(`/diagram-mitigations/${id}`),
};

// Collaborators API
export const collaboratorsApi = {
  list: (productId: number) => api.get(`/products/${productId}/collaborators`),
  add: (productId: number, data: { user_id: number; role: 'owner' | 'editor' | 'viewer' }) =>
    api.post(`/products/${productId}/collaborators`, data),
  update: (productId: number, userId: number, data: { role: 'owner' | 'editor' | 'viewer' }) =>
    api.put(`/products/${productId}/collaborators/${userId}`, data),
  remove: (productId: number, userId: number) =>
    api.delete(`/products/${productId}/collaborators/${userId}`),
};

// CWE API
export const cwesApi = {
  list: (params?: { search?: string; category?: string }) => api.get('/cwes', { params }),
  get: (id: number) => api.get(`/cwes/${id}`),
  getCVEs: (id: number) => api.get(`/cwes/${id}/cves`),
  getForThreat: (threatId: number) => api.get(`/threats/${threatId}/cwes`),
  linkToThreat: (threatId: number, cweId: number) => api.post(`/threats/${threatId}/cwes`, { cwe_id: cweId }),
  unlinkFromThreat: (threatId: number, cweId: number) => api.delete(`/threats/${threatId}/cwes/${cweId}`),
};

// CVE API
export const cvesApi = {
  list: (params?: { keyword?: string; cwe_id?: string; severity?: string; vendor?: string; product?: string; limit?: number; offset?: number }) => api.get('/cves', { params }),
  get: (cveId: string) => api.get(`/cves/${cveId}`),
  search: (params: { keyword?: string; cwe_id?: string; vendor?: string; product?: string; version?: string; severity?: string; fetch_from_nvd?: boolean }) => api.post('/cves/search', params),
  byTechnology: (params: { vendor?: string; product: string; version?: string }) => api.get('/cves/by-technology', { params }),
  forDiagram: (diagramId: number) => api.get(`/diagrams/${diagramId}/cves`),
  forProduct: (productId: number) => api.get(`/products/${productId}/cves`),
  summary: (productIds?: number[]) => api.get('/cves/summary', { params: productIds ? { product_ids: productIds.join(',') } : {} }),
};

// Technology Stack API
export const technologyStacksApi = {
  listForDiagram: (diagramId: number) => api.get(`/diagrams/${diagramId}/technology-stacks`),
  listForElement: (diagramId: number, elementId: string) => api.get(`/diagrams/${diagramId}/elements/${elementId}/technology-stacks`),
  create: (diagramId: number, data: { element_id: string; technology_name: string; version?: string; vendor?: string }) => api.post(`/diagrams/${diagramId}/technology-stacks`, data),
  update: (id: number, data: { technology_name?: string; version?: string; vendor?: string }) => api.put(`/technology-stacks/${id}`, data),
  delete: (id: number) => api.delete(`/technology-stacks/${id}`),
  getCVEs: (id: number) => api.get(`/technology-stacks/${id}/cves`),
};

// Analytics API
export const analyticsApi = {
  summary: (params?: { product_id?: number; diagram_id?: number; model_id?: number }) => api.get('/analytics/summary', { params }),
  riskHeatmap: (params?: { product_id?: number; diagram_id?: number; model_id?: number }) => api.get('/analytics/risk-heatmap', { params }),
  categoryDistribution: (params?: { product_id?: number; diagram_id?: number; model_id?: number }) => api.get('/analytics/category-distribution', { params }),
  statusDistribution: (params?: { product_id?: number; diagram_id?: number; model_id?: number }) => api.get('/analytics/status-distribution', { params }),
  severityDistribution: (params?: { product_id?: number; diagram_id?: number; model_id?: number }) => api.get('/analytics/severity-distribution', { params }),
  cveSeverity: (params?: { product_id?: number }) => api.get('/analytics/cve-severity', { params }),
  techVulnerability: (params?: { product_id?: number; diagram_id?: number }) => api.get('/analytics/tech-vulnerability', { params }),
};

// Reports API
export const reportsApi = {
  threatModel: (params: { product_id: number; diagram_id?: number }) => api.get('/reports/threat-model', { params }),
};

// Pentest API
export const pentestsApi = {
  list: (params?: { product_id?: number }) => api.get('/pentests', { params }),
  get: (id: number) => api.get(`/pentests/${id}`),
  create: (data: any) => api.post('/pentests', data),
  update: (id: number, data: any) => api.put(`/pentests/${id}`, data),
  delete: (id: number) => api.delete(`/pentests/${id}`),
};

// Pentest Findings API
export const pentestFindingsApi = {
  list: (params?: { pentest_id?: number; severity?: string; status?: string }) => api.get('/pentest-findings', { params }),
  get: (id: number) => api.get(`/pentest-findings/${id}`),
  create: (data: any) => api.post('/pentest-findings', data),
  update: (id: number, data: any) => api.put(`/pentest-findings/${id}`, data),
  delete: (id: number) => api.delete(`/pentest-findings/${id}`),
  linkCWE: (findingId: number, cweId: number) => api.post(`/pentest-findings/${findingId}/cwes`, { cwe_id: cweId }),
  unlinkCWE: (findingId: number, cweId: number) => api.delete(`/pentest-findings/${findingId}/cwes/${cweId}`),
  linkCVE: (findingId: number, cveId: number) => api.post(`/pentest-findings/${findingId}/cves`, { cve_id: cveId }),
  unlinkCVE: (findingId: number, cveId: number) => api.delete(`/pentest-findings/${findingId}/cves/${cveId}`),
  linkThreat: (findingId: number, dtId: number) => api.post(`/pentest-findings/${findingId}/diagram-threats`, { diagram_threat_id: dtId }),
  unlinkThreat: (findingId: number, dtId: number) => api.delete(`/pentest-findings/${findingId}/diagram-threats/${dtId}`),
  listRetests: (findingId: number) => api.get(`/pentest-findings/${findingId}/retests`),
  createRetest: (findingId: number, data: any) => api.post(`/pentest-findings/${findingId}/retests`, data),
  deleteRetest: (findingId: number, retestId: number) => api.delete(`/pentest-findings/${findingId}/retests/${retestId}`),
  uploadEvidence: (findingId: number, file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post(`/pentest-findings/${findingId}/evidence/upload`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },
  addNote: (findingId: number, content: string) => api.post(`/pentest-findings/${findingId}/evidence/note`, { note_content: content }),
  deleteEvidence: (id: number) => api.delete(`/pentest-evidence/${id}`),
};

// Pentest Analytics & Reports
export const pentestAnalyticsApi = {
  summary: (params?: { product_id?: number }) => api.get('/analytics/pentest-summary', { params }),
  vendorComparison: (params?: { product_id?: number }) => api.get('/analytics/vendor-comparison', { params }),
};

export const pentestReportsApi = {
  generate: (params: { product_id: number; pentest_id?: number }) => api.get('/reports/pentest', { params }),
};

// Pentest Assignments API
export const pentestAssignmentsApi = {
  list: (pentestId: number) => api.get(`/pentests/${pentestId}/assignments`),
  assign: (pentestId: number, userId: number) => api.post(`/pentests/${pentestId}/assign`, { user_id: userId }),
  unassign: (pentestId: number, userId: number) => api.delete(`/pentests/${pentestId}/assign/${userId}`),
};

// Users API
export const usersApi = {
  list: () => api.get('/users'),
};

export default api;
