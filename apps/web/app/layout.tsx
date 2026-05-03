import type { Metadata } from "next";
import "./styles.css";

export const metadata: Metadata = {
  title: "TrustVault Lite",
  description: "Secure client evidence portal demo"
};

export default function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

