import { type ReactNode } from "react";
import Sidebar from "./Sidebar";
import Header from "./Header";
import { useUIStore } from "../../store/uiStore";

export default function Layout({ children }: { children: ReactNode }) {
  const sidebarOpen = useUIStore((s) => s.sidebarOpen);
  return (
    <div className="flex min-h-screen">
      {sidebarOpen && <Sidebar />}
      <div className={`flex flex-1 flex-col ${sidebarOpen ? "ml-56" : ""}`}>
        <Header />
        <main className="flex-1 p-6">{children}</main>
      </div>
    </div>
  );
}
