import { NextResponse } from "next/server";
import { getUser } from "../../../../../lib/auth";
import { prisma } from "../../../../../lib/db";

type RouteContext = { params: { id: string } };

export async function GET(_request: Request, { params }: RouteContext) {
  const user = await getUser();
  if (!user) {
    return NextResponse.json({ error: "Sign in to view saved conversations." }, { status: 401 });
  }

  const conversation = await prisma.chatConversation.findFirst({
    where: { id: params.id, userId: user.id },
    select: {
      id: true,
      title: true,
      messages: {
        orderBy: { createdAt: "asc" },
        select: { id: true, role: true, content: true, createdAt: true },
      },
    },
  });
  if (!conversation) {
    return NextResponse.json({ error: "Conversation not found." }, { status: 404 });
  }

  return NextResponse.json({ conversation });
}

export async function DELETE(_request: Request, { params }: RouteContext) {
  const user = await getUser();
  if (!user) {
    return NextResponse.json({ error: "Sign in to delete saved conversations." }, { status: 401 });
  }

  const deleted = await prisma.chatConversation.deleteMany({
    where: { id: params.id, userId: user.id },
  });
  if (deleted.count === 0) {
    return NextResponse.json({ error: "Conversation not found." }, { status: 404 });
  }

  return NextResponse.json({ ok: true });
}
