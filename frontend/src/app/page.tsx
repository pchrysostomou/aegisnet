import { redirect } from "next/navigation";

/** There is no dashboard home yet; the queue is where an analyst starts. */
export default function HomePage() {
  redirect("/incidents");
}
