import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getUser } from "@/lib/auth";

export async function GET(req: Request) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const url = new URL(req.url);
  const q = url.searchParams.get("q")?.trim() ?? "";
  const classification = url.searchParams.get("c")?.trim() ?? "";
  const sort = url.searchParams.get("sort")?.trim() ?? "newest";
  const page = Math.max(1, parseInt(url.searchParams.get("page") ?? "1", 10));
  const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit") ?? "20", 10)));
  const days = url.searchParams.get("days") ? parseInt(url.searchParams.get("days")!, 10) : null;

  // Build where clause
  const where: any = { userId: user.id };

  if (q) {
    where.OR = [
      { originalUrl: { contains: q } },
      { normalizedUrl: { contains: q } },
      { hostname: { contains: q } },
    ];
  }

  if (classification && classification !== "ALL") {
    // Support matching both legacy "Safe" and new "NO THREAT DETECTED"
    if (classification === "NO THREAT DETECTED" || classification === "Safe") {
      where.classification = { in: ["NO THREAT DETECTED", "Safe"] };
    } else {
      where.classification = classification;
    }
  }

  if (days && !isNaN(days) && days > 0) {
    const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    where.createdAt = { gte: cutoff };
  }

  // Sorting
  let orderBy: any = { createdAt: "desc" };
  if (sort === "oldest") orderBy = { createdAt: "asc" };
  else if (sort === "risk_high") orderBy = { score: "desc" };
  else if (sort === "risk_low") orderBy = { score: "asc" };

  const [total, scans] = await Promise.all([
    prisma.scan.count({ where }),
    prisma.scan.findMany({
      where,
      orderBy,
      skip: (page - 1) * limit,
      take: limit,
      select: {
        id: true,
        originalUrl: true,
        normalizedUrl: true,
        hostname: true,
        ipAddress: true,
        score: true,
        classification: true,
        status: true,
        createdAt: true,
      },
    }),
  ]);

  return NextResponse.json({
    scans,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
    },
  });
}

export async function DELETE(req: Request) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const url = new URL(req.url);
  const id = url.searchParams.get("id");
  const clearAll = url.searchParams.get("clearAll") === "true";

  if (clearAll) {
    const deleted = await prisma.scan.deleteMany({
      where: { userId: user.id },
    });
    return NextResponse.json({ ok: true, deleted: deleted.count });
  }

  if (!id) {
    return NextResponse.json({ error: "Scan ID is required" }, { status: 400 });
  }

  const result = await prisma.scan.deleteMany({
    where: { id, userId: user.id },
  });

  if (result.count === 0) {
    return NextResponse.json({ error: "Scan not found or unauthorized" }, { status: 404 });
  }

  return NextResponse.json({ ok: true, deleted: result.count });
}
