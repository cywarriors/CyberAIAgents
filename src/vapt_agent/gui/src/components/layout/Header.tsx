import { Menu, Moon, Sun } from "lucide-react";
import { useUIStore } from "../../store/uiStore";

export default function Header() {
  const { toggleSidebar, darkMode, toggleDarkMode } = useUIStore();

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-gray-800 bg-gray-950/80 px-6 backdrop-blur">
      <button
        onClick={toggleSidebar}
        className="rounded-lg p-2 text-gray-400 hover:bg-gray-800 hover:text-white"
        aria-label="Toggle sidebar"
      >
        <Menu className="h-5 w-5" />
      </button>

      <div className="flex items-center gap-3">
        <button
          onClick={toggleDarkMode}
          className="rounded-lg p-2 text-gray-400 hover:bg-gray-800 hover:text-white"
          aria-label="Toggle theme"
        >
          {darkMode ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
        </button>
      </div>
    </header>
  );
}
