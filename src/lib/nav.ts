import type { Section } from "@/stores/route-store";

/** Single source of truth for navigation: rail, mobile bar, page headers and ⌘K. */
export interface NavSub {
  id: string;
  label: string;
  hint: string;
  keywords?: string;
}

export interface NavSection {
  route: Section;
  label: string;
  short: string;
  hint: string;
  icon: "now" | "radio" | "network" | "pulse" | "system" | "admin";
  subs: NavSub[];
  /** On phones this section shares the bottom-bar tab of another section (keeps the bar at 5). */
  mobileTab?: Section;
}

export const NAV: NavSection[] = [
  {
    route: "/",
    label: "Now",
    short: "Now",
    hint: "Live link health at a glance",
    icon: "now",
    subs: [],
  },
  {
    route: "/cellular",
    label: "Radio",
    short: "Radio",
    hint: "Carrier, bands, cells and antennas",
    icon: "radio",
    subs: [
      { id: "profiles", label: "Profiles & MBN", hint: "APN profiles and carrier firmware", keywords: "apn sim iccid mbn carrier firmware" },
      { id: "bands", label: "Band Lock", hint: "Restrict LTE / NR bands and network mode", keywords: "band lock mode nr5g lte sa nsa" },
      { id: "tuning", label: "PHY & Tuning", hint: "5G PHY/QoS/SSB telemetry, CA/MIMO & Dual-SIM", keywords: "sim phy mcs pathloss hpue sar cdrx a3 cipher 5qi ambr ssb tuning radio baseband mimo ca" },
      { id: "lock", label: "Cell Lock", hint: "Pin a tower by PCI and ARFCN", keywords: "cell lock pci earfcn arfcn tower deadman bypass" },
      { id: "align", label: "Antenna Aim", hint: "Peak-hold RX0–RX3 while you point", keywords: "antenna alignment aim mimo rsrp peak" },
      { id: "scan", label: "Cell Scan", hint: "Neighbours and full cell survey", keywords: "neighbor neighbour scan survey qscan" },
    ],
  },
  {
    route: "/network",
    label: "Network",
    short: "Net",
    hint: "LAN, passthrough, policy, usage and VPN",
    icon: "network",
    subs: [
      { id: "lan", label: "LAN & Link", hint: "Bridge, DHCP, passthrough, Ethernet PHY", keywords: "lan ipa passthrough dhcp ethernet phy speed mac" },
      { id: "policy", label: "TTL · MTU · DNS", hint: "Packet header and resolver policy", keywords: "ttl hop limit mtu dns" },
      { id: "usage", label: "Data Usage", hint: "Daily and monthly cellular totals", keywords: "usage data quota bytes monthly" },
      { id: "dataplane", label: "Data Plane", hint: "Native QRTR/QMI, Netlink, IPA offload and kernel tuning", keywords: "dataplane qrtr qmi netlink ipa offload rmnet qmap rps fq_codel" },
      { id: "warp", label: "Cloudflare", hint: "Remote Access (Cloudflare Tunnel) & Outbound VPN (WARP)", keywords: "cloudflare tunnel cloudflared warp 1.1.1.1 wireguard zero trust teams vpn remote access ssh wgcf" },
      { id: "tailscale", label: "Tailscale", hint: "Tailnet access, subnet routes and exit nodes", keywords: "tailscale vpn mesh remote tailnet exit node subnet ssh" },
    ],
  },
  {
    route: "/diagnostics",
    label: "Diagnostics",
    short: "Diag",
    hint: "Speed, latency, AT console, SMS and events",
    icon: "pulse",
    subs: [
      { id: "speedtest", label: "Speedtest", hint: "Throughput and bufferbloat grade", keywords: "speedtest cloudflare bufferbloat throughput" },
      { id: "health", label: "Health Watch", hint: "LinkWatch connection monitor", keywords: "health quecwatch watchdog monitor" },
      { id: "latency", label: "Latency", hint: "Ping history and keep-alive", keywords: "latency ping keepalive rrc" },
      { id: "at", label: "AT Console", hint: "Send AT commands to the modem", keywords: "at terminal command console" },
      { id: "sms", label: "SMS", hint: "Inbox and compose", keywords: "sms text message inbox" },
      { id: "events", label: "Events", hint: "Handovers, recoveries and failover timeline", keywords: "events log timeline handover failover carrier aggregation registration reboot" },
    ],
  },
  {
    route: "/system",
    label: "System",
    short: "System",
    hint: "Identity, logs, updates and security",
    icon: "system",
    subs: [
      { id: "hardware", label: "Identity & Thermals", hint: "IMEI, ICCID, firmware, temperatures", keywords: "imei iccid firmware temperature thermal" },
      { id: "internals", label: "Internals", hint: "Daemon, reconciler, services", keywords: "internals reconcile daemon service cpu" },
      { id: "logs", label: "Logs", hint: "logread and cellcored log", keywords: "logs logread syslog" },
      { id: "alerts", label: "Maintenance", hint: "Scheduled reboots, notifications and failover", keywords: "alerts email reboot schedule maintenance notifications ntfy webhook alertmanager failover sms forward" },
      { id: "ota", label: "Updates", hint: "Package feed and upgrades", keywords: "ota update upgrade opkg package" },
      { id: "backup", label: "Config Backup", hint: "Export and restore CellCore settings", keywords: "backup restore export import config settings bundle" },
      { id: "security", label: "Security & Units", hint: "Password, API tokens, audit log, units", keywords: "password security units celsius miles api token audit log" },
    ],
  },
  {
    route: "/admin",
    label: "Admin",
    short: "Admin",
    hint: "OpenWrt administration without LuCI",
    icon: "admin",
    mobileTab: "/system",
    subs: [
      { id: "system", label: "Time & Name", hint: "Hostname, timezone and NTP", keywords: "hostname timezone ntp clock time sync" },
      { id: "access", label: "SSH Access", hint: "Dropbear settings and authorized keys", keywords: "ssh dropbear keys authorized_keys password port" },
      { id: "services", label: "Services", hint: "Start, stop and enable init scripts", keywords: "services init.d daemon start stop restart enable" },
      { id: "cron", label: "Scheduled Tasks", hint: "Root crontab", keywords: "cron crontab schedule scheduled tasks" },
      { id: "processes", label: "Processes", hint: "CPU and memory per process", keywords: "processes ps top kill signal cpu memory" },
      { id: "software", label: "Software", hint: "opkg packages and free space", keywords: "opkg packages install remove software update" },
      { id: "firewall", label: "Firewall", hint: "Zones, port forwards and traffic rules", keywords: "firewall port forward redirect rule zone nat dmz fw4" },
      { id: "mwan3", label: "Multi-WAN", hint: "mwan3 interface and policy status", keywords: "mwan3 multiwan failover policy tracking" },
      { id: "status", label: "Routes & Connections", hint: "Interfaces, routes, neighbours, conntrack", keywords: "interfaces routes routing table arp neighbours conntrack connections" },
      { id: "dhcp", label: "DHCP & DNS", hint: "Static leases, active leases, dnsmasq", keywords: "dhcp dns dnsmasq leases static reservation hostname" },
      { id: "tools", label: "Net Tools", hint: "Ping, traceroute and nslookup", keywords: "ping traceroute nslookup dns lookup diagnostics" },
      { id: "backup", label: "Backup & Restore", hint: "Config backup and restore", keywords: "backup restore sysupgrade luci legacy" },
    ],
  },
];

export function sectionFor(route: Section): NavSection {
  return NAV.find((n) => n.route === route) ?? NAV[0];
}

export function subFor(route: Section, sub: string | null): NavSub | null {
  const s = sectionFor(route);
  return s.subs.find((x) => x.id === sub) ?? s.subs[0] ?? null;
}
