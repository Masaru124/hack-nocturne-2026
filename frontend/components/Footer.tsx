import Link from "next/link";
import React from "react";

const Footer = () => {
  return (
    <footer className="bg-black border-t border-gray-800 pt-20 pb-10 px-4">
      <div className="max-w-6xl mx-auto">
        {/* Big branding */}
        <div className="text-center mb-16">
          <h2 className="text-6xl md:text-8xl font-black tracking-tighter bg-linear-to-r from-gray-700 via-blue-600 to-gray-700 bg-clip-text text-transparent select-none">
            SCAMSHIELD
          </h2>
          <p className="text-gray-500 mt-4 text-lg">
            Community-driven. AI-powered. Blockchain-secured.
          </p>
        </div>

        {/* Links */}
        <div className="flex flex-wrap justify-center gap-8 text-sm text-gray-500 mb-10">
          <Link href="/" className="hover:text-white transition-colors">
            Home
          </Link>
          <Link
            href="/dashboard"
            className="hover:text-white transition-colors"
          >
            Dashboard
          </Link>
          <Link
            href="/analytics"
            className="hover:text-white transition-colors"
          >
            Analytics
          </Link>
          <Link href="/registry" className="hover:text-white transition-colors">
            Registry
          </Link>
          <Link href="/report" className="hover:text-white transition-colors">
            Report Scam
          </Link>
        </div>

        {/* Divider */}
        <div className="border-t border-gray-800 pt-8 flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-gray-600">
          <p>© 2026 ScamShield. Built at Hack-Nocturne 2026.</p>
          <p className="flex items-center gap-2">
            Powered by
            <span className="text-blue-500 font-medium">Polygon</span>+
            <span className="text-blue-500 font-medium">Claude AI</span>
          </p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
