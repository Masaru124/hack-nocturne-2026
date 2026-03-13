import React from "react";

const Navbar = () => {
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-gray-950/80 backdrop-blur-md border-b border-gray-800">
      <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
        {/* LOGO */}
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-blue-500 rounded-lg flex items-center justify-center text-lg">
            🛡️
          </div>
          <span className="text-xl font-bold text-white tracking-tight">
            Scam<span className="text-blue-400">Shield</span>
          </span>
        </div>

        {/* LINKS */}
        <div className="hidden md:flex items-center gap-8 text-sm text-gray-400">
          <a href="/dashboard" className="hover:text-white transition-colors">
            Dashboard
          </a>
          <a href="/analytics" className="hover:text-white transition-colors">
            Analytics
          </a>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
