import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = {
  title: "AegisNet",
  description: "Defensive network threat detection lab — web placeholder",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "system-ui, sans-serif", margin: "2rem", maxWidth: "48rem" }}>
        {children}
      </body>
    </html>
  );
}
