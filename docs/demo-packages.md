# Demo Packages

TuskScan uses two intentionally unsafe Sui packages to show memory-assisted auditing.

## Package A

Path: `move/demo-package-a`

Purpose: first audit teaches the exploit memory.

Vulnerable surfaces:

- `vault::admin_sweep(&mut Treasury, recipient)` is a public entry function with an admin-like name and no capability parameter.
- `vault::withdraw_all(&mut Treasury)` is a public entry function with value-moving naming and mutable shared-object access.
- `Treasury has key, store`, so the object lifecycle should be reviewed.

Publish:

```powershell
cd E:\GithubProjects\sui-overflow\tuskscan\move\demo-package-a
sui client publish --gas-budget 100000000
```

After publishing, record the package ID here:

```text
PACKAGE_A_ID=<paste published package id>
```

## Package B

Path: `move/demo-package-b`

Purpose: second audit should recall the exploit memory learned from Package A.

Vulnerable surfaces:

- `reserve::owner_config(&mut Reserve, next_owner)` is a public entry function with owner/config naming and no capability parameter.
- `reserve::claim_treasury(&mut Reserve)` is a public entry function with claim/treasury naming and mutable shared-object access.
- `Reserve has key, store`, so the object lifecycle should be reviewed.

Publish:

```powershell
cd E:\GithubProjects\sui-overflow\tuskscan\move\demo-package-b
sui client publish --gas-budget 100000000
```

After publishing, record the package ID here:

```text
PACKAGE_B_ID=<paste published package id>
```

## Demo Order

1. Publish `move/tuskscan` and set `NEXT_PUBLIC_TUSKSCAN_PACKAGE_ID` to the published TuskScan package ID.
2. Publish Package A and Package B.
3. Run TuskScan against Package A.
4. Run TuskScan against Package B.
5. Confirm Package B includes at least one memory-assisted finding.
