import { NextResponse } from "next/server";
import { getUser } from "../../../../lib/auth";
import { prisma } from "../../../../lib/db";

export async function GET() {
  const user = await getUser();
  if (!user) {
    return NextResponse.json(
      { error: "Sign in to view saved conversations." },
      { status: 401 }
    );
  }

  const conversations = await prisma.chatConversation.findMany({
    where: { userId: user.id },
    orderBy: { updatedAt: "desc" },
    take: 50,
    select: {
      id: true,
      title: true,
      updatedAt: true,
      _count: { select: { messages: true } },
    },
  });

  return NextResponse.json({
    conversations: conversations.map(({ _count, ...conversation }) => ({
      ...conversation,
      messageCount: _count.messages,
    })),
  });
}
