import { useSubRoute } from "../stores/route-store";
import { PageHeader } from "../components/ui";
import { SystemTimeView } from "./admin/SystemTimeView";
import { AccessView } from "./admin/AccessView";
import { ServicesView } from "./admin/ServicesView";
import { CronView } from "./admin/CronView";
import { ProcessesView } from "./admin/ProcessesView";
import { SoftwareView } from "./admin/SoftwareView";
import { FirewallView } from "./admin/FirewallView";
import { MwanView } from "./admin/MwanView";
import { NetStatusView } from "./admin/NetStatusView";
import { DhcpView } from "./admin/DhcpView";
import { ToolsView } from "./admin/ToolsView";
import { BackupView } from "./admin/BackupView";

const ADMIN_TABS = ["system", "access", "services", "cron", "processes", "software", "firewall", "mwan3", "status", "dhcp", "tools", "backup"] as const;
type AdminTab = (typeof ADMIN_TABS)[number];

export function AdminPage() {
  const [tab, setTab] = useSubRoute<AdminTab>("/admin", ADMIN_TABS, "system");
  return (
    <div className="space-y-6">
      <PageHeader section="/admin" sub={tab} onSubChange={(id) => setTab(id as AdminTab)} />
      <div key={tab} className="qm-rise">
        {tab === "system" && <SystemTimeView />}
        {tab === "access" && <AccessView />}
        {tab === "services" && <ServicesView />}
        {tab === "cron" && <CronView />}
        {tab === "processes" && <ProcessesView />}
        {tab === "software" && <SoftwareView />}
        {tab === "firewall" && <FirewallView />}
        {tab === "mwan3" && <MwanView />}
        {tab === "status" && <NetStatusView />}
        {tab === "dhcp" && <DhcpView />}
        {tab === "tools" && <ToolsView />}
        {tab === "backup" && <BackupView />}
      </div>
    </div>
  );
}
