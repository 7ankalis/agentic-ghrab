import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

export const useOverview = () => useQuery({ queryKey: ["overview"], queryFn: api.overview });
export const useKpis = () => useQuery({ queryKey: ["kpis"], queryFn: api.kpis });
export const useFindings = () => useQuery({ queryKey: ["findings"], queryFn: api.findings });
export const useFinding = (qid: number | null) =>
  useQuery({ queryKey: ["finding", qid], queryFn: () => api.finding(qid!), enabled: qid != null });
export const useAttackPaths = () => useQuery({ queryKey: ["attackPaths"], queryFn: api.attackPaths });
export const useGraph = () => useQuery({ queryKey: ["graph"], queryFn: api.graph });
export const useCorrelation = () => useQuery({ queryKey: ["correlation"], queryFn: api.correlation });
export const useCompliance = () => useQuery({ queryKey: ["compliance"], queryFn: api.compliance });
export const useTeams = () => useQuery({ queryKey: ["teams"], queryFn: api.teams });
export const useProviders = () => useQuery({ queryKey: ["providers"], queryFn: api.providers });
