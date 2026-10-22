import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getUser } from "@/lib/auth";

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const user = await getUser();
  const scan = await prisma.scan.findUnique({
    where: { id: params.id },
  });

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  // If scan is assigned to a user, enforce ownership
  if (scan.userId && (!user || scan.userId !== user.id)) {
    return NextResponse.json({ error: "Unauthorized access to scan" }, { status: 403 });
  }

  return NextResponse.json({
    scan: {
      ...scan,
      findings: JSON.parse(scan.findings || "[]"),
      providerResults: JSON.parse(scan.providerResults || "{}"),
      domainInfo: JSON.parse(scan.domainInfo || "{}"),
      certificateInfo: scan.certificateInfo ? JSON.parse(scan.certificateInfo) : null,
      redirectChain: JSON.parse(scan.redirectChain || "[]"),
      notes: JSON.parse(scan.notes || "[]"),
    },
  });
}

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const result = await prisma.scan.deleteMany({
    where: { id: params.id, userId: user.id },
  });

  if (result.count === 0) {
    return NextResponse.json({ error: "Scan not found or unauthorized" }, { status: 404 });
  }

  return NextResponse.json({ ok: true, deleted: result.count });
}
