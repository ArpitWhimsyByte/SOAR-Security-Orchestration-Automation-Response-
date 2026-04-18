import { useState } from "react";
import SoarDashboard from "../SoarDashboard.jsx";
import AdminLogin from "./AdminLogin.jsx";

export default function App() {
  const [adminUser, setAdminUser] = useState(null);

  if (!adminUser) {
    return <AdminLogin onLogin={setAdminUser} />;
  }

  return <SoarDashboard adminUser={adminUser} onLogout={() => setAdminUser(null)} />;
}
