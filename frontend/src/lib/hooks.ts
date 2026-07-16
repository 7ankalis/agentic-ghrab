import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

export const useOverview = () => useQuery({ queryKey: ["overview"], queryFn: api.overview });
export const useKpis = () => useQuery({ queryKey: ["kpis"], queryFn: api.kpis });
export const useFindings = () => useQuery({ queryKey: ["findings"], queryFn: api.findings });
export const useFinding = (qid: number | null) =>
  useQuery({ queryKey: ["finding", qid], queryFn: () => api.finding(qid!), enabled: qid != null });
export const useRemediation = (qid: number | null) =>
  useQuery({
    queryKey: ["remediation", qid],
    queryFn: () => api.getRemediation(qid!),
    enabled: qid != null,
    staleTime: Infinity,
  });
export const useAttackPaths = () => useQuery({ queryKey: ["attackPaths"], queryFn: api.attackPaths });
export const useVerification = () => useQuery({ queryKey: ["verification"], queryFn: api.verification });
export const useGraph = () => useQuery({ queryKey: ["graph"], queryFn: api.graph });
export const useCorrelation = () => useQuery({ queryKey: ["correlation"], queryFn: api.correlation });
export const useCompliance = () => useQuery({ queryKey: ["compliance"], queryFn: api.compliance });
export const useTeams = () => useQuery({ queryKey: ["teams"], queryFn: api.teams });
export const useDatasets = () => useQuery({ queryKey: ["datasets"], queryFn: api.datasets });
export const useProviders = () => useQuery({ queryKey: ["providers"], queryFn: api.providers });
export const useRuns = () => useQuery({ queryKey: ["runs"], queryFn: api.runs });
