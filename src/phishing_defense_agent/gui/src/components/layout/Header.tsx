import { Menu, Moon, Sun } from "lucide-react";
import { useUIStore } from "../../store/uiStore";

export default function Header() {
  const { toggleSidebar, darkMode, toggleDarkMode } = useUIStore();
  return (
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-gray-800 bg-gray-950/80 px-6 backdrop-blur">
      <button onClick={toggleSidebar} className="text-gray-400 hover:text-white">
        <Menu className="h-5 w-5" />
      </button>
      <button onClick={toggleDarkMode} className="text-gray-400 hover:text-white">
        {darkMode ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
      </button>
    </header>
  );
}
