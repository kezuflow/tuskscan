"use client";

import { getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import {
  SuiClientProvider,
  WalletProvider,
  createNetworkConfig,
  type ThemeVars,
} from "@mysten/dapp-kit";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";

const { networkConfig } = createNetworkConfig({
  mainnet: { network: "mainnet", url: getJsonRpcFullnodeUrl("mainnet") },
  testnet: { network: "testnet", url: getJsonRpcFullnodeUrl("testnet") },
});

const defaultNetwork =
  process.env.NEXT_PUBLIC_TUSKSCAN_NETWORK === "mainnet" ? "mainnet" : "testnet";

const tuskScanWalletTheme: ThemeVars = {
  blurs: {
    modalOverlay: "blur(2px)",
  },
  backgroundColors: {
    dropdownMenu: "#171613",
    dropdownMenuSeparator: "#2b2a26",
    iconButton: "transparent",
    iconButtonHover: "#1d2a17",
    modalOverlay: "rgba(11 11 10 / 72%)",
    modalPrimary: "#171613",
    modalSecondary: "#11110f",
    outlineButtonHover: "#1d2a17",
    primaryButton: "#1d2a17",
    primaryButtonHover: "#24361d",
    walletItemHover: "#1d2a17",
    walletItemSelected: "#14200f",
  },
  borderColors: {
    outlineButton: "#575047",
  },
  colors: {
    body: "#d6cfb9",
    bodyDanger: "#ff615c",
    bodyMuted: "#8a8175",
    iconButton: "#d6cfb9",
    outlineButton: "#d6cfb9",
    primaryButton: "#8ed06c",
  },
  fontSizes: {
    large: "16px",
    medium: "13px",
    small: "12px",
    xlarge: "18px",
  },
  fontWeights: {
    bold: "800",
    medium: "700",
    normal: "400",
  },
  radii: {
    large: "4px",
    medium: "3px",
    small: "2px",
    xlarge: "6px",
  },
  shadows: {
    primaryButton: "none",
    walletItemSelected: "none",
  },
  typography: {
    fontFamily: "var(--font-geist-mono), Consolas, monospace",
    fontStyle: "normal",
    letterSpacing: "0",
    lineHeight: "1.3",
  },
};

export function Providers({ children }: { children: ReactNode }) {
  const [queryClient] = useState(() => new QueryClient());

  return (
    <QueryClientProvider client={queryClient}>
      <SuiClientProvider defaultNetwork={defaultNetwork} networks={networkConfig}>
        <WalletProvider autoConnect theme={tuskScanWalletTheme}>{children}</WalletProvider>
      </SuiClientProvider>
    </QueryClientProvider>
  );
}
