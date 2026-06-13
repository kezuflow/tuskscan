import type { Metadata } from "next";
import { VT323 } from "next/font/google";
import "@mysten/dapp-kit/dist/index.css";
import "./globals.css";

import { Providers } from "./providers";

const vt323 = VT323({
  weight: "400",
  subsets: ["latin"],
  variable: "--font-vt323",
});

export const metadata: Metadata = {
  title: "TuskScan",
  description:
    "Walrus-backed AI pre-audits for deployed Sui Move packages.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={vt323.variable}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
