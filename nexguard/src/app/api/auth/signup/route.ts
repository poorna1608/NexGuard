import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { prisma } from "@/lib/db";
import { createSession } from "@/lib/auth";
const schema = z.object({ name: z.string().min(1).max(80), email: z.string().email(), password: z.string().min(10).max(128), confirm: z.string() })
  .refine((d) => d.password === d.confirm, { message: "Passwords do not match", path: ["confirm"] });
export async function POST(req: Request) {
  const p = schema.safeParse(await req.json().catch(() => null));
  if (!p.success) return NextResponse.json({ error: p.error.issues[0].message }, { status: 400 });
  const email = p.data.email.toLowerCase();
  if (await prisma.user.findUnique({ where: { email } })) return NextResponse.json({ error: "Email already registered" }, { status: 409 });
  const user = await prisma.user.create({ data: { email, name: p.data.name, passwordHash: await bcrypt.hash(p.data.password, 12) } });
  await createSession(user.id);
  return NextResponse.json({ ok: true }, { status: 201 });
}
