import { SignJWT, jwtVerify } from "jose";
import { cookies } from "next/headers";
import { prisma } from "./db";
const secret = () => {
  const s = process.env.AUTH_SECRET;
  if (!s || s.length < 32) throw new Error("AUTH_SECRET must be set (32+ chars)");
  return new TextEncoder().encode(s);
};
export async function createSession(userId: string) {
  const token = await new SignJWT({ sub: userId }).setProtectedHeader({ alg: "HS256" }).setExpirationTime("7d").sign(secret());
  cookies().set("ng_session", token, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/", maxAge: 604800 });
}
export function destroySession() { cookies().delete("ng_session"); }
export async function getUser() {
  const t = cookies().get("ng_session")?.value;
  if (!t) return null;
  try {
    const { payload } = await jwtVerify(t, secret());
    return await prisma.user.findUnique({ where: { id: String(payload.sub) }, select: { id: true, email: true, name: true } });
  } catch { return null; }
}
