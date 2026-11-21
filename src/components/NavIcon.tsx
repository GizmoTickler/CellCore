import { Activity, Cpu, Network, Radio, Sunrise, Wrench } from "lucide-react";
import type { NavSection } from "../lib/nav";

export function NavIcon({ name, className }: { name: NavSection["icon"]; className?: string }) {
  switch (name) {
    case "now":
      return <Sunrise className={className} />;
    case "radio":
      return <Radio className={className} />;
    case "network":
      return <Network className={className} />;
    case "pulse":
      return <Activity className={className} />;
    case "system":
      return <Cpu className={className} />;
    case "admin":
      return <Wrench className={className} />;
  }
}
