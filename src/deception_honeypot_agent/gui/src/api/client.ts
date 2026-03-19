import axios from "axios";

const api = axios.create({ baseURL: "/" });

export const getDashboard = () =>
  api.get("/api/v1/dashboard/deception").then((r) => r.data);

export const getDecoys = () =>
  api.get("/api/v1/decoys").then((r) => r.data);

export const getInteractions = (limit = 50, offset = 0) =>
  api.get("/api/v1/interactions", { params: { limit, offset } }).then((r) => r.data);

export const getAlerts = (limit = 50, offset = 0) =>
  api.get("/api/v1/alerts", { params: { limit, offset } }).then((r) => r.data);

export const getCoverage = () =>
  api.get("/api/v1/coverage").then((r) => r.data);

export const getProfiles = () =>
  api.get("/api/v1/attacker-profiles").then((r) => r.data);

export const getStatistics = () =>
  api.get("/admin/statistics").then((r) => r.data);
