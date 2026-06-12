import type { NormalizedPackageSnapshot, PackageSummary } from "@repo/shared";

export const safePackageSnapshot: NormalizedPackageSnapshot = {
  fetchedAt: "2026-06-12T00:00:00.000Z",
  modules: [
    {
      functions: [
        {
          isEntry: true,
          name: "update_config",
          parameters: [
            { isMutableReference: false, isSharedObjectLike: false, raw: "&AdminCap" },
            {
              isMutableReference: true,
              isSharedObjectLike: false,
              raw: "&mut Config",
            },
          ],
          returns: [],
          visibility: "private",
        },
        {
          isEntry: true,
          name: "claim_receipt",
          parameters: [
            { isMutableReference: false, isSharedObjectLike: false, raw: "&ClaimCap" },
          ],
          returns: [],
          visibility: "private",
        },
      ],
      name: "vault",
      structs: [
        {
          abilities: ["key"],
          fields: [{ name: "id", type: "UID" }],
          name: "Config",
        },
      ],
    },
  ],
  network: "testnet",
  packageDigest: "safe-fixture",
  packageId: "0x1234",
  source: "sui-normalized-modules",
};

export const vulnerablePackageSnapshot: NormalizedPackageSnapshot = {
  fetchedAt: "2026-06-12T00:00:00.000Z",
  modules: [
    {
      functions: [
        {
          isEntry: true,
          name: "admin_sweep",
          parameters: [
            {
              isMutableReference: true,
              isSharedObjectLike: true,
              raw: "&mut Treasury",
            },
          ],
          returns: [],
          visibility: "public",
        },
        {
          isEntry: true,
          name: "withdraw_all",
          parameters: [
            {
              isMutableReference: true,
              isSharedObjectLike: true,
              raw: "&mut Treasury",
            },
          ],
          returns: [],
          visibility: "public",
        },
      ],
      name: "vault",
      structs: [
        {
          abilities: ["key", "store"],
          fields: [{ name: "id", type: "UID" }],
          name: "Treasury",
        },
      ],
    },
  ],
  network: "testnet",
  packageDigest: "vulnerable-fixture",
  packageId: "0xabcd",
  source: "sui-normalized-modules",
};

export const vulnerablePackageSummary: PackageSummary = {
  fetchedAt: vulnerablePackageSnapshot.fetchedAt,
  functionCount: 2,
  moduleCount: 1,
  network: vulnerablePackageSnapshot.network,
  packageDigest: vulnerablePackageSnapshot.packageDigest,
  packageId: vulnerablePackageSnapshot.packageId,
  structCount: 1,
};

export const demoPackageASnapshot: NormalizedPackageSnapshot = {
  ...vulnerablePackageSnapshot,
  packageDigest: "demo-package-a-fixture",
  packageId: "0xa",
};

export const demoPackageBSnapshot: NormalizedPackageSnapshot = {
  fetchedAt: "2026-06-12T00:00:00.000Z",
  modules: [
    {
      functions: [
        {
          isEntry: true,
          name: "claim_treasury",
          parameters: [
            {
              isMutableReference: true,
              isSharedObjectLike: true,
              raw: "&mut Reserve",
            },
          ],
          returns: [],
          visibility: "public",
        },
        {
          isEntry: true,
          name: "owner_config",
          parameters: [
            {
              isMutableReference: true,
              isSharedObjectLike: true,
              raw: "&mut Reserve",
            },
            { isMutableReference: false, isSharedObjectLike: false, raw: "address" },
          ],
          returns: [],
          visibility: "public",
        },
      ],
      name: "reserve",
      structs: [
        {
          abilities: ["key", "store"],
          fields: [{ name: "id", type: "UID" }],
          name: "Reserve",
        },
      ],
    },
  ],
  network: "testnet",
  packageDigest: "demo-package-b-fixture",
  packageId: "0xb",
  source: "sui-normalized-modules",
};
