import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { getUser } from "@/lib/auth";
import { prisma } from "@/lib/db";

const updateSchema = z.object({
  name: z.string().min(1, "Name is required").max(80),
  currentPassword: z.string().optional(),
  newPassword: z.string().min(8, "New password must be at least 8 characters").optional(),
});

export async function GET() {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const [scanCounts, totalScans] = await Promise.all([
    prisma.scan.groupBy({
      by: ["classification"],
      where: { userId: user.id },
      _count: true,
    }),
    prisma.scan.count({ where: { userId: user.id } }),
  ]);

  const stats = {
    total: totalScans,
    malicious: scanCounts.find((s) => s.classification === "MALICIOUS")?._count || 0,
    suspicious: scanCounts.find((s) => s.classification === "SUSPICIOUS")?._count || 0,
    clean: scanCounts.find((s) => s.classification === "NO THREAT DETECTED")?._count || 0,
    incomplete: scanCounts.find((s) => s.classification === "SCAN INCOMPLETE")?._count || 0,
  };

  const dbUser = await prisma.user.findUnique({
    where: { id: user.id },
    select: { id: true, name: true, email: true, createdAt: true },
  });

  return NextResponse.json({ user: dbUser, stats });
}

export async function PUT(req: Request) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json().catch(() => null);
  const parsed = updateSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.issues[0]?.message || "Invalid input" }, { status: 400 });
  }

  const { name, currentPassword, newPassword } = parsed.data;

  const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
  if (!dbUser) return NextResponse.json({ error: "User not found" }, { status: 404 });

  const updateData: { name: string; passwordHash?: string } = { name };

  if (newPassword) {
    if (!currentPassword) {
      return NextResponse.json(
        { error: "Current password is required to change your password" },
        { status: 400 }
      );
    }
    const isMatch = await bcrypt.compare(currentPassword, dbUser.passwordHash);
    if (!isMatch) {
      return NextResponse.json({ error: "Current password is incorrect" }, { status: 400 });
    }
    updateData.passwordHash = await bcrypt.hash(newPassword, 12);
  }

  const updated = await prisma.user.update({
    where: { id: user.id },
    data: updateData,
    select: { id: true, name: true, email: true, createdAt: true },
  });

  return NextResponse.json({ ok: true, user: updated });
}
