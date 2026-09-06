import type { Metadata } from "next";
import type { ReactNode } from "react";

import { Masthead } from "@/components/masthead";

import "./globals.css";

export const metadata: Metadata = {
  title: "AegisNet",
  description: "Defensive network threat detection lab — analyst dashboard",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <a className="skip-link" href="#content">
          Skip to content
        </a>
        <Masthead />
        <div id="content">{children}</div>
      </body>
    </html>
  );
}
