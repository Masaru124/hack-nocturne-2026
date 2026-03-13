import OpenAI from "openai";

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// Discord webhook integration
async function sendDiscordAlert(
  url,
  attackType,
  riskScore,
  confidence,
  indicators,
) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;

  if (!webhookUrl || riskScore < 70) {
    return; // Only alert for high-risk detections
  }

  const color =
    riskScore >= 80 ? 0xff0000 : riskScore >= 60 ? 0xff6600 : 0xffff00;

  const embed = {
    title: "⚡ AI High-Risk Detection",
    description: "AI-powered analysis detected a dangerous scam",
    color: color,
    fields: [
      {
        name: "URL",
        value: url.length > 80 ? url.substring(0, 80) + "..." : url,
        inline: false,
      },
      {
        name: "Attack Type",
        value: attackType,
        inline: true,
      },
      {
        name: "Risk Score",
        value: `${riskScore}/100`,
        inline: true,
      },
      {
        name: "Confidence",
        value: `${confidence}%`,
        inline: true,
      },
      {
        name: "Indicators",
        value: indicators.slice(0, 3).join("\n"),
        inline: false,
      },
    ],
    timestamp: new Date().toISOString(),
    footer: {
      text: "ScamShield Real-time Alert",
    },
  };

  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        embeds: [embed],
        username: "ScamShield Bot",
        avatar_url: "https://i.imgur.com/3Z4j2rM.png",
      }),
    });

    if (response.ok) {
      console.log("Discord alert sent successfully");
    }
  } catch (error) {
    console.error("Failed to send Discord alert:", error);
  }
}

function extractSignals(url) {
  try {
    const u = new URL(url);
    const domain = u.hostname;
    const path = u.pathname.toLowerCase();
    const query = u.search.toLowerCase();

    const suspiciousKeywords = [
      "airdrop",
      "reward",
      "bonus",
      "claim",
      "verify",
      "wallet",
      "crypto",
      "login",
      "secure",
      "update",
      "connect",
      "mint",
      "approve",
      "stake",
      "swap",
      "drain",
      "private",
      "seed",
      "phrase",
      "mnemonic",
      "keystore",
      "metamask",
      "trustwallet",
    ];

    const highRiskKeywords = [
      "private-key",
      "seed-phrase",
      "mnemonic",
      "approve-all",
      "drain",
      "steal",
      "hack",
      "malware",
      "virus",
    ];

    const domainSignals = suspiciousKeywords.filter((k) =>
      domain.toLowerCase().includes(k),
    );
    const pathSignals = suspiciousKeywords.filter((k) => path.includes(k));
    const querySignals = suspiciousKeywords.filter((k) => query.includes(k));
    const highRiskSignals = highRiskKeywords.filter((k) =>
      url.toLowerCase().includes(k),
    );

    // Check for suspicious patterns
    const hasIPPattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain);
    const hasShortDomain = domain.length < 8;
    const hasManyDashes = (domain.match(/-/g) || []).length > 2;
    const hasSuspiciousTLD = /\.(tk|ml|ga|cf|gq|xyz|top|click|cyou)$/i.test(
      domain,
    );

    return {
      domain,
      length: url.length,
      keywords: [
        ...new Set([...domainSignals, ...pathSignals, ...querySignals]),
      ],
      highRiskKeywords: highRiskSignals,
      patterns: {
        hasIPPattern,
        hasShortDomain,
        hasManyDashes,
        hasSuspiciousTLD,
      },
      riskFactors: [
        ...(highRiskSignals.length ? ["high_risk_keywords"] : []),
        ...(hasIPPattern ? ["ip_address"] : []),
        ...(hasShortDomain ? ["short_domain"] : []),
        ...(hasManyDashes ? ["excessive_dashes"] : []),
        ...(hasSuspiciousTLD ? ["suspicious_tld"] : []),
      ],
    };
  } catch {
    return null;
  }
}

function getQuickAnalysis(url, signals) {
  // Fast heuristic analysis for immediate response
  let quickRisk = 0;
  let quickType = "unknown";
  const quickIndicators = [];

  // URL pattern analysis
  if (signals.patterns.hasIPPattern) {
    quickRisk += 25;
    quickIndicators.push("IP address in URL");
  }
  if (signals.patterns.hasSuspiciousTLD) {
    quickRisk += 15;
    quickIndicators.push("Suspicious top-level domain");
  }
  if (signals.patterns.hasShortDomain) {
    quickRisk += 10;
    quickIndicators.push("Unusually short domain");
  }

  // Keyword analysis
  const phishingKeywords = [
    "login",
    "secure",
    "verify",
    "account",
    "metamask",
    "wallet",
  ];
  const drainerKeywords = [
    "approve",
    "connect",
    "drain",
    "mint",
    "stake",
    "swap",
  ];
  const prizeKeywords = ["airdrop", "reward", "bonus", "claim", "giveaway"];
  const malwareKeywords = ["download", "update", "install", "virus", "malware"];

  const hasPhishing = signals.keywords.some((k) =>
    phishingKeywords.includes(k),
  );
  const hasDrainer = signals.keywords.some((k) => drainerKeywords.includes(k));
  const hasPrize = signals.keywords.some((k) => prizeKeywords.includes(k));
  const hasMalware = signals.keywords.some((k) => malwareKeywords.includes(k));

  if (signals.highRiskKeywords.length > 0) {
    quickRisk += 30;
    quickIndicators.push("High-risk keywords detected");
  }

  // Determine likely attack type
  if (hasPhishing && !hasDrainer && !hasPrize) {
    quickType = "phishing";
    quickRisk += 20;
    quickIndicators.push("Phishing indicators");
  } else if (hasDrainer) {
    quickType = "drainer";
    quickRisk += 25;
    quickIndicators.push("Wallet drain indicators");
  } else if (hasPrize) {
    quickType = "prize";
    quickRisk += 15;
    quickIndicators.push("Reward scam indicators");
  } else if (hasMalware) {
    quickType = "malware";
    quickRisk += 20;
    quickIndicators.push("Malware indicators");
  }

  return {
    attackType: quickType,
    riskScore: Math.min(100, quickRisk),
    confidence: Math.min(95, 60 + signals.keywords.length * 5),
    indicators: quickIndicators.slice(0, 5),
  };
}

export async function POST(req) {
  try {
    const { url } = await req.json();

    if (!url) {
      return Response.json({ error: "missing_url" }, { status: 400 });
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch {
      return Response.json({ error: "invalid_url" }, { status: 400 });
    }

    const signals = extractSignals(url);
    if (!signals) {
      return Response.json({ error: "analysis_failed" }, { status: 400 });
    }

    // Get quick analysis for immediate response
    const quickAnalysis = getQuickAnalysis(url, signals);

    // If high confidence quick result, return immediately
    if (quickAnalysis.confidence >= 75 || quickAnalysis.riskScore >= 70) {
      return Response.json(quickAnalysis);
    }

    // Otherwise, do detailed AI analysis
    const systemPrompt = `
You are an elite cybersecurity scam detection engine with real-time analysis capabilities.

Your job is to classify scam URLs with high accuracy and speed.

Attack types:
phishing - login/credential theft, fake wallet connections, account verification scams
drainer - crypto wallet drain, approve-all scams, malicious smart contracts  
prize - fake rewards, airdrops, giveaways, bonus claims
malware - file downloads, fake updates, virus installations, trojans
unknown - suspicious but unclear intent

Analysis factors:
- URL structure and domain patterns
- Keyword presence and context
- Attack vector indicators
- Risk factor combinations

Return STRICT JSON with high confidence scores.
`;

    const userPrompt = `
URL: ${url}
Domain: ${signals.domain}
URL Length: ${signals.length}
Suspicious Keywords: ${signals.keywords.join(", ")}
High-Risk Keywords: ${signals.highRiskKeywords.join(", ")}
Risk Patterns: ${signals.riskFactors.join(", ")}

Quick Analysis: ${JSON.stringify(quickAnalysis)}

Provide detailed analysis:

{
 "attackType": "phishing | drainer | prize | malware | unknown",
 "riskScore": number (0-100),
 "confidence": number (0-100),
 "indicators": ["specific_reason1", "specific_reason2", "specific_reason3"]
}
`;

    const completion = await client.chat.completions.create({
      model: "gpt-4o-mini",
      temperature: 0.1,
      max_tokens: 200,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
    });

    const aiResult = JSON.parse(completion.choices[0].message.content);

    // Merge quick and AI analysis for best result
    const finalResult = {
      attackType: aiResult.attackType || quickAnalysis.attackType,
      riskScore: Math.max(quickAnalysis.riskScore, aiResult.riskScore || 0),
      confidence: Math.max(quickAnalysis.confidence, aiResult.confidence || 0),
      indicators: [
        ...new Set([
          ...quickAnalysis.indicators,
          ...(aiResult.indicators || []),
        ]),
      ].slice(0, 8),
    };

    // Send Discord alert for high-risk detections
    await sendDiscordAlert(
      url,
      finalResult.attackType,
      finalResult.riskScore,
      finalResult.confidence,
      finalResult.indicators,
    );

    return Response.json(finalResult);
  } catch (err) {
    console.error("Analysis error:", err);

    // Fallback to basic analysis
    const signals = extractSignals(url);
    const fallback = getQuickAnalysis(url, signals);

    return Response.json({
      ...fallback,
      indicators: [...fallback.indicators, "analysis_fallback"],
    });
  }
}
