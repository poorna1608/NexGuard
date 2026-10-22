import { NextResponse } from "next/server";
import { z } from "zod";
import { scanUrlAsync } from "@/lib/scanner";
import { getUser } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { limited } from "@/lib/rateLimit";

const schema = z.object({
  url: z.string().min(1, "URL is required").max(2048, "URL is too long (max 2048 characters)"),
  deepScan: z.boolean().optional().default(true),
});

export async function POST(req: Request) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "local";

  // Rate limit: 30 requests per minute per IP
  if (limited(`scan:${ip}`, 30, 60_000)) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Please wait a moment before running more scans." },
      { status: 429 }
    );
  }

  const body = await req.json().catch(() => null);
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: parsed.error.issues[0]?.message || "Invalid URL submitted" },
      { status: 400 }
    );
  }

  try {
    const result = await scanUrlAsync(parsed.data.url, { deepScan: parsed.data.deepScan });
    const user = await getUser();

    let id: string | null = null;
    let saved = false;

    if (user) {
      const scanRecord = await prisma.scan.create({
        data: {
          userId: user.id,
          originalUrl: result.originalUrl,
          normalizedUrl: result.normalizedUrl,
          hostname: result.hostname,
          ipAddress: result.ipAddress,
          score: result.score,
          classification: result.classification,
          status: result.status,
          findings: JSON.stringify(result.findings),
          providerResults: JSON.stringify(result.providerResults),
          domainInfo: JSON.stringify(result.domainInfo),
          certificateInfo: result.certificateInfo ? JSON.stringify(result.certificateInfo) : null,
          redirectChain: JSON.stringify(result.redirectChain),
          notes: JSON.stringify(result.notes),
        },
      });
      id = scanRecord.id;
      saved = true;
    }

    return NextResponse.json({
      ...result,
      id,
      saved,
    });
  } catch (err: any) {
    console.error("Scan error:", err);
    return NextResponse.json(
      { error: `Scan operation failed: ${err.message || "Internal server error"}` },
      { status: 500 }
    );
  }
}
