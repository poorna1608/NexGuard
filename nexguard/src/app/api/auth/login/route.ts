import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { prisma } from "@/lib/db";
import { createSession } from "@/lib/auth";
import { limited } from "@/lib/rateLimit";
const schema = z.object({ email: z.string().email(), password: z.string().min(1) });
export async function POST(req: Request) {
  if (limited("login:" + (req.headers.get("x-forwarded-for") ?? "local"), 10)) return NextResponse.json({ error: "Too many attempts" }, { status: 429 });
  const p = schema.safeParse(await req.json().catch(() => null));
  if (!p.success) return NextResponse.json({ error: "Invalid input" }, { status: 400 });
  const user = await prisma.user.findUnique({ where: { email: p.data.email.toLowerCase() } });
  if (!user || !(await bcrypt.compare(p.data.password, user.passwordHash))) return NextResponse.json({ error: "Invalid email or password" }, { status: 401 });
  await createSession(user.id);
  return NextResponse.json({ ok: true });
}
