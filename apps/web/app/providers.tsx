"use client";

import { getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import {
  SuiClientProvider,
  WalletProvider,
  createNetworkConfig,
} from "@mysten/dapp-kit";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";

const { networkConfig } = createNetworkConfig({
  mainnet: { network: "mainnet", url: getJsonRpcFullnodeUrl("mainnet") },
  testnet: { network: "testnet", url: getJsonRpcFullnodeUrl("testnet") },
});

const defaultNetwork =
  process.env.NEXT_PUBLIC_TUSKSCAN_NETWORK === "mainnet" ? "mainnet" : "testnet";

export function Providers({ children }: { children: ReactNode }) {
  const [queryClient] = useState(() => new QueryClient());

  return (
    <QueryClientProvider client={queryClient}>
      <SuiClientProvider defaultNetwork={defaultNetwork} networks={networkConfig}>
        <WalletProvider autoConnect>{children}</WalletProvider>
      </SuiClientProvider>
    </QueryClientProvider>
  );
}
