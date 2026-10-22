import { redirect } from "next/navigation";
import { getUser } from "@/lib/auth";
import { AuthForm } from "@/components/AuthForm";

export const metadata = {
  title: "Sign In – NexGuard SOC",
};

export default async function LoginPage() {
  const user = await getUser();
  if (user) redirect("/dashboard");

  return (
    <div className="py-12">
      <AuthForm mode="login" />
    </div>
  );
}
