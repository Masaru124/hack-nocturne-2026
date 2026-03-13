import OpenAI from "openai";
import { z } from "zod";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ─── Zod Schemas ──────────────────────────────────────────────────────────────

const AttackTypeSchema = z.enum([
  "phishing",
  "drainer",
  "prize",
  "malware",
  "unknown",
]);

/** What we accept from the request body */
const RequestSchema = z.object({
  url: z
    .string()
    .describe("The URL to analyze for potential scams")
    .min(1, "url cannot be empty")
    .max(2048, "url too long")
    .trim()
    .transform((val) => (val.startsWith("http") ? val : `https://${val}`))
    .refine(
      (val) => {
        try {
          new URL(val);
          return true;
        } catch {
          return false;
        }
      },
      { message: "url is not a valid URL" },
    ),
});

/** What the OpenAI model must return — validated before we trust it */
const AIResponseSchema = z.object({
  attackType: AttackTypeSchema.catch("unknown"),
  riskScore: z.number().min(0).max(100).catch(0),
  confidence: z.number().min(0).max(100).catch(0),
  indicators: z.array(z.string().max(200)).max(10).catch([]),
});

/** The shape every caller receives — success or error, always consistent */
const SuccessResponseSchema = z.object({
  ok: z.literal(true),
  attackType: AttackTypeSchema,
  riskScore: z.number().int().min(0).max(100),
  confidence: z.number().int().min(0).max(100),
  indicators: z.array(z.string()),
  source: z.enum(["ai", "heuristic", "fallback"]),
  url: z.string().url(),
  domain: z.string(),
  analysedAt: z.string().datetime(),
});

const ErrorResponseSchema = z.object({
  ok: z.literal(false),
  error: z.string(),
  code: z.enum([
    "MISSING_URL",
    "INVALID_URL",
    "URL_TOO_LONG",
    "ANALYSIS_FAILED",
    "INTERNAL_ERROR",
  ]),
});

// Union — anything coming out of this route matches one of these two shapes
export type ApiResponse =
  | z.infer<typeof SuccessResponseSchema>
  | z.infer<typeof ErrorResponseSchema>;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function clamp(n: number, min = 0, max = 100) {
  return Math.round(Math.max(min, Math.min(max, n)));
}

function errorResponse(
  code: z.infer<typeof ErrorResponseSchema>["code"],
  message: string,
  status: number,
) {
  const body: z.infer<typeof ErrorResponseSchema> = {
    ok: false,
    error: message,
    code,
  };
  return Response.json(body, { status });
}

// ─── Signal extraction (unchanged logic, typed output) ────────────────────────

interface Signals {
  domain: string;
  length: number;
  keywords: string[];
  highRiskKeywords: string[];
  patterns: {
    hasIPPattern: boolean;
    hasShortDomain: boolean;
    hasManyDashes: boolean;
    hasSuspiciousTLD: boolean;
  };
  riskFactors: string[];
}

function extractSignals(url: string): Signals | null {
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

    const inDomain = suspiciousKeywords.filter((k) =>
      domain.toLowerCase().includes(k),
    );
    const inPath = suspiciousKeywords.filter((k) => path.includes(k));
    const inQuery = suspiciousKeywords.filter((k) => query.includes(k));
    const highRisk = highRiskKeywords.filter((k) =>
      url.toLowerCase().includes(k),
    );

    const hasIPPattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain);
    const hasShortDomain = domain.replace(/^www\./, "").length < 8;
    const hasManyDashes = (domain.match(/-/g) ?? []).length > 2;
    const hasSuspiciousTLD =
      /\.(tk|ml|ga|cf|gq|xyz|top|click|cyou|ru|pw)$/i.test(domain);

    return {
      domain,
      length: url.length,
      keywords: [...new Set([...inDomain, ...inPath, ...inQuery])],
      highRiskKeywords: highRisk,
      patterns: {
        hasIPPattern,
        hasShortDomain,
        hasManyDashes,
        hasSuspiciousTLD,
      },
      riskFactors: [
        ...(highRisk.length ? ["high_risk_keywords"] : []),
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

// ─── Heuristic analysis ───────────────────────────────────────────────────────

interface HeuristicResult {
  attackType: z.infer<typeof AttackTypeSchema>;
  riskScore: number;
  confidence: number;
  indicators: string[];
}

function getQuickAnalysis(signals: Signals): HeuristicResult {
  let risk = 0;
  const indicators: string[] = [];

  if (signals.patterns.hasIPPattern) {
    risk += 25;
    indicators.push("IP address used as hostname");
  }
  if (signals.patterns.hasSuspiciousTLD) {
    risk += 15;
    indicators.push("Suspicious top-level domain");
  }
  if (signals.patterns.hasShortDomain) {
    risk += 10;
    indicators.push("Unusually short domain");
  }
  if (signals.patterns.hasManyDashes) {
    risk += 10;
    indicators.push("Excessive hyphens in domain");
  }
  if (signals.highRiskKeywords.length) {
    risk += 30;
    indicators.push(
      "High-risk keywords: " + signals.highRiskKeywords.slice(0, 3).join(", "),
    );
  }

  const phishingKW = [
    "login",
    "secure",
    "verify",
    "account",
    "metamask",
    "wallet",
  ];
  const drainerKW = ["approve", "connect", "drain", "mint", "stake", "swap"];
  const prizeKW = ["airdrop", "reward", "bonus", "claim", "giveaway"];
  const malwareKW = ["download", "update", "install", "virus", "malware"];

  const hasPhishing = signals.keywords.some((k) => phishingKW.includes(k));
  const hasDrainer = signals.keywords.some((k) => drainerKW.includes(k));
  const hasPrize = signals.keywords.some((k) => prizeKW.includes(k));
  const hasMalware = signals.keywords.some((k) => malwareKW.includes(k));

  let attackType: z.infer<typeof AttackTypeSchema> = "unknown";

  if (hasDrainer) {
    attackType = "drainer";
    risk += 25;
    indicators.push("Wallet drain indicators");
  } else if (hasPhishing) {
    attackType = "phishing";
    risk += 20;
    indicators.push("Credential phishing indicators");
  } else if (hasPrize) {
    attackType = "prize";
    risk += 15;
    indicators.push("Fake reward/prize indicators");
  } else if (hasMalware) {
    attackType = "malware";
    risk += 20;
    indicators.push("Malware distribution indicators");
  }

  return {
    attackType,
    riskScore: clamp(risk),
    confidence: clamp(60 + signals.keywords.length * 5),
    indicators: indicators.slice(0, 5),
  };
}

// ─── Discord alert ────────────────────────────────────────────────────────────

async function sendDiscordAlert(
  url: string,
  result: HeuristicResult,
): Promise<void> {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl || result.riskScore < 70) return;

  const color =
    result.riskScore >= 85
      ? 0xff0000
      : result.riskScore >= 70
        ? 0xff6600
        : 0xffff00;

  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "ScamShield Bot",
        embeds: [
          {
            title: "⚡ High-Risk Scam Detected",
            color,
            fields: [
              { name: "URL", value: url.slice(0, 100), inline: false },
              { name: "Type", value: result.attackType, inline: true },
              { name: "Risk", value: `${result.riskScore}/100`, inline: true },
              {
                name: "Confidence",
                value: `${result.confidence}%`,
                inline: true,
              },
              {
                name: "Indicators",
                value: result.indicators.slice(0, 3).join("\n") || "—",
                inline: false,
              },
            ],
            timestamp: new Date().toISOString(),
            footer: { text: "ScamShield Real-time Alert" },
          },
        ],
      }),
    });
  } catch (err) {
    console.error("[Discord] alert failed:", err);
    // Never throw — Discord failure must not affect the API response
  }
}

// ─── Route handler ────────────────────────────────────────────────────────────

export async function POST(req: Request): Promise<Response> {
  // 1. Parse + validate request body
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return errorResponse("MISSING_URL", "Request body must be valid JSON", 400);
  }

  const parsed = RequestSchema.safeParse(body);
  if (!parsed.success) {
    const firstError = parsed.error.errors[0];
    const code =
      firstError.path[0] === "url" && firstError.message.includes("required")
        ? "MISSING_URL"
        : firstError.message.includes("valid URL")
          ? "INVALID_URL"
          : firstError.message.includes("too long")
            ? "URL_TOO_LONG"
            : "INVALID_URL";
    return errorResponse(code, firstError.message, 400);
  }

  const { url } = parsed.data;

  // 2. Extract signals — always works if URL parsed
  const signals = extractSignals(url);
  if (!signals) {
    return errorResponse(
      "ANALYSIS_FAILED",
      "Could not extract signals from URL",
      422,
    );
  }

  const domain = signals.domain;
  const analysedAt = new Date().toISOString();
  const heuristic = getQuickAnalysis(signals);

  // 3. Return heuristic immediately if confident enough
  if (heuristic.confidence >= 75 || heuristic.riskScore >= 70) {
    void sendDiscordAlert(url, heuristic); // fire and forget
    const response: z.infer<typeof SuccessResponseSchema> = {
      ok: true,
      source: "heuristic",
      url,
      domain,
      analysedAt,
      attackType: heuristic.attackType,
      riskScore: heuristic.riskScore,
      confidence: heuristic.confidence,
      indicators: heuristic.indicators,
    };
    return Response.json(response);
  }

  // 4. Low-confidence → call OpenAI for deeper analysis
  try {
    const completion = await client.chat.completions.create({
      model: "gpt-4o-mini",
      temperature: 0.1,
      max_tokens: 250,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content: `You are a cybersecurity scam detection engine.
Classify the given URL into one of: phishing, drainer, prize, malware, unknown.
Return ONLY a JSON object — no prose, no markdown.
Schema: { attackType, riskScore (0-100), confidence (0-100), indicators: string[] }`,
        },
        {
          role: "user",
          content: JSON.stringify({
            url,
            domain,
            urlLength: signals.length,
            suspiciousKW: signals.keywords,
            highRiskKW: signals.highRiskKeywords,
            riskFactors: signals.riskFactors,
            heuristicResult: heuristic,
          }),
        },
      ],
    });

    // 5. Validate the AI response with Zod — never trust raw JSON from a model
    const rawAI = JSON.parse(completion.choices[0].message.content ?? "{}");
    const aiParsed = AIResponseSchema.safeParse(rawAI);

    // If AI returned garbage, fall back to heuristic (never fail the request)
    const ai = aiParsed.success ? aiParsed.data : heuristic;

    const merged: z.infer<typeof SuccessResponseSchema> = {
      ok: true,
      source: aiParsed.success ? "ai" : "heuristic",
      url,
      domain,
      analysedAt,
      attackType:
        ai.attackType !== "unknown" ? ai.attackType : heuristic.attackType,
      riskScore: clamp(Math.max(heuristic.riskScore, ai.riskScore)),
      confidence: clamp(Math.max(heuristic.confidence, ai.confidence)),
      indicators: [
        ...new Set([...heuristic.indicators, ...ai.indicators]),
      ].slice(0, 8),
    };

    void sendDiscordAlert(url, merged);
    return Response.json(merged);
  } catch (err) {
    // 6. OpenAI failed entirely — return heuristic as fallback, never 500
    console.error("[OpenAI] analysis failed:", err);
    const fallback: z.infer<typeof SuccessResponseSchema> = {
      ok: true,
      source: "fallback",
      url,
      domain,
      analysedAt,
      ...heuristic,
    };
    return Response.json(fallback);
  }
}
