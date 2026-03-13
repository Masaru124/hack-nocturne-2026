import React from "react";

const Features = () => {
  return (
    <div className="">
      <section className="bg-black py-24 px-4">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-bold text-center mb-4">How It Works</h2>
          <p className="text-center text-gray-400 mb-16">
            Three steps to permanent scam protection
          </p>

          <div className="grid md:grid-cols-3 gap-8">
            {[
              {
                step: "01",
                icon: "🔍",
                title: "Paste & Scan",
                desc: "Paste any suspicious message or link. Our AI analyzes it in seconds using a two-layer detection system.",
              },
              {
                step: "02",
                icon: "🤖",
                title: "AI Analysis",
                desc: "Get an instant risk score, category, red flags, and verdict powered by advanced AI models.",
              },
              {
                step: "03",
                icon: "⛓️",
                title: "Store on Blockchain",
                desc: "Confirmed scams are stored permanently on Polygon — tamper-proof, censorship-resistant, forever.",
              },
            ].map(({ step, icon, title, desc }) => (
              <div
                key={step}
                className="bg-gray-800/50 border border-gray-700  p-6 hover:border-blue-500/50 transition-colors"
              >
                <div className="flex items-center gap-3 mb-4">
                  <span className="text-3xl">{icon}</span>
                  <span className="text-blue-400 font-mono text-sm font-bold">
                    {step}
                  </span>
                </div>
                <h3 className="text-lg font-semibold mb-2">{title}</h3>
                <p className="text-gray-400 text-sm leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
      <section className="py-24 px-4 bg-black">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-bold text-center mb-4">
            Built for Everyone
          </h2>
          <p className="text-center text-gray-400 mb-16">
            No crypto knowledge required
          </p>

          <div className="grid md:grid-cols-2 gap-6">
            {[
              {
                icon: "🌐",
                title: "Web App",
                desc: "Scan and report from any browser. No installation needed.",
              },
              {
                icon: "🔌",
                title: "Chrome Extension",
                desc: "Auto-warns you before clicking malicious links while browsing.",
              },
              {
                icon: "✈️",
                title: "Telegram Bot",
                desc: "Forward any suspicious message to our bot and get instant analysis.",
              },
              {
                icon: "📊",
                title: "Public Registry",
                desc: "Browse all confirmed scams stored on-chain. Transparent and open.",
              },
            ].map(({ icon, title, desc }) => (
              <div
                key={title}
                className="flex items-start gap-4 bg-gray-900 border border-gray-800  p-5 hover:border-blue-500/30 transition-colors"
              >
                <div className="text-2xl mt-1">{icon}</div>
                <div>
                  <h3 className="font-semibold mb-1">{title}</h3>
                  <p className="text-gray-400 text-sm">{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
};

export default Features;
