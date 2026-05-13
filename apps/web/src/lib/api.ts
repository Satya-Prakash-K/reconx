/** API client for ReconX backend */

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

class ApiClient {
  private token: string | null = null;

  setToken(token: string) {
    this.token = token;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${API_URL}${path}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(error.detail || `API Error: ${response.status}`);
    }

    return response.json();
  }

  // Auth
  async login(username: string, password: string) {
    return this.request<{ access_token: string; refresh_token: string }>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
  }

  // Programs
  async getPrograms() {
    return this.request<any[]>("/api/v1/programs/");
  }

  async createProgram(data: any) {
    return this.request("/api/v1/programs/", { method: "POST", body: JSON.stringify(data) });
  }

  // Scans
  async getScans(workspaceId?: string) {
    const params = workspaceId ? `?workspace_id=${workspaceId}` : "";
    return this.request<any[]>(`/api/v1/scans/${params}`);
  }

  async createScan(data: any) {
    return this.request("/api/v1/scans/", { method: "POST", body: JSON.stringify(data) });
  }

  async cancelScan(scanId: string) {
    return this.request(`/api/v1/scans/${scanId}/cancel`, { method: "POST" });
  }

  // Findings
  async getFindings(workspaceId?: string, severity?: string) {
    const params = new URLSearchParams();
    if (workspaceId) params.set("workspace_id", workspaceId);
    if (severity) params.set("severity", severity);
    return this.request<any[]>(`/api/v1/findings/?${params}`);
  }

  async searchFindings(query: string) {
    return this.request(`/api/v1/findings/search?q=${encodeURIComponent(query)}`);
  }

  // AI
  async generateSummary(workspaceId: string) {
    return this.request(`/api/v1/ai/summarize/${workspaceId}`, { method: "POST" });
  }

  async getAttackPaths(workspaceId: string) {
    return this.request(`/api/v1/ai/attack-paths/${workspaceId}`);
  }

  async semanticSearch(query: string) {
    return this.request(`/api/v1/ai/semantic-search?q=${encodeURIComponent(query)}`);
  }

  // Workspaces
  async getWorkspaces(programId?: string) {
    const params = programId ? `?program_id=${programId}` : "";
    return this.request<any[]>(`/api/v1/workspaces/${params}`);
  }

  // Health
  async healthCheck() {
    return this.request<{ status: string }>("/health");
  }
}

export const api = new ApiClient();
export default api;
