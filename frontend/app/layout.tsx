import type { Metadata } from "next";
import { AppShell } from "@/app/components/app-shell";
import "./globals.css";

export const metadata: Metadata = {
  title: "FORENSIX | Digital Forensics Operations",
  description: "Evidence-led investigation workspace for digital forensics teams.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
