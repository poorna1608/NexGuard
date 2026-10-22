import { redirect } from "next/navigation";
import { getUser } from "@/lib/auth";
import { AuthForm } from "@/components/AuthForm";

export const metadata = {
  title: "Create Account – NexGuard SOC",
};

export default async function SignupPage() {
  const user = await getUser();
  if (user) redirect("/dashboard");

  return (
    <div className="py-12">
      <AuthForm mode="signup" />
    </div>
  );
}
