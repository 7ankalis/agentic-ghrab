import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Overview from "./features/overview/Overview";
import Findings from "./features/findings/Findings";
import AttackPaths from "./features/attackpaths/AttackPaths";
import Correlation from "./features/correlation/Correlation";
import Teams from "./features/teams/Teams";
import Compliance from "./features/compliance/Compliance";
import Analyst from "./features/analyst/Analyst";
import Logs from "./features/logs/Logs";
import Settings from "./features/settings/Settings";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="findings" element={<Findings />} />
        <Route path="attack-paths" element={<AttackPaths />} />
        <Route path="correlation" element={<Correlation />} />
        <Route path="teams" element={<Teams />} />
        <Route path="compliance" element={<Compliance />} />
        <Route path="analyst" element={<Analyst />} />
        <Route path="logs" element={<Logs />} />
        <Route path="settings" element={<Settings />} />
      </Route>
    </Routes>
  );
}
