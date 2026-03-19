import axios from "axios";
const api = axios.create({ baseURL: "" });
export default api;

export const getDashboard = () => api.get("/api/v1/dashboard/security").then(r => r.data);
export const getFindings = (params?: object) => api.get("/api/v1/findings", { params }).then(r => r.data);
export const getScans = () => api.get("/api/v1/scans").then(r => r.data);
export const getSBOMs = () => api.get("/api/v1/sbom").then(r => r.data);
export const getPolicyVerdicts = () => api.get("/api/v1/policy/verdicts").then(r => r.data);
export const triggerScan = (payload: object) => api.post("/api/v1/scans", payload).then(r => r.data);
