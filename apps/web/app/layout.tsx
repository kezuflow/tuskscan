import type { Metadata } from "next";
import localFont from "next/font/local";
import "@mysten/dapp-kit/dist/index.css";
import "./globals.css";

import { Providers } from "./providers";

const geistSans = localFont({
  src: "./fonts/GeistVF.woff",
  variable: "--font-geist-sans",
});

const geistMono = localFont({
  src: "./fonts/GeistMonoVF.woff",
  variable: "--font-geist-mono",
});

export const metadata: Metadata = {
  title: "TuskScan",
  description:
    "Walrus-backed AI pre-audits for deployed Sui Move packages.",
  icons: {
    icon: [{ rel: "icon", type: "image/webp", url: "/tusk-logo.webp" }],
    shortcut: [{ rel: "shortcut icon", type: "image/webp", url: "/tusk-logo.webp" }],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable}`}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
