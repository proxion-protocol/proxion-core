# Proxion Core (EI₀)

> **Reference Implementation (Witness)**

This repository contains the **Existential Instantiation Zero (EI₀)** for Proxion.

## Purpose

The purpose of `proxion-core` is to prove that the Universal Architecture defined in `proxion-spec` is implementable. It serves as a **witness** to the specification.

**It is explicitly NOT:**
*   A product.
*   The only way to implement Proxion.
*   Optimized for high performance or specific application constraints.

## Constraints & Assumptions (EI)

As a reference implementation, this codebase is intentionally minimal and "boring":

*   **No Network Stack**: Core logic is pure functions or local state transitions; transport is abstracted.
*   **No Identity Provider**: Keys are generated locally; no dependence on external OIDC/DID resolvers.
*   **In-Memory/Simple Storage**: No database requirements.

## Scope

This repository implements:
*   Capability Issuance (signing).
*   Capability Verification (checking signatures and chains).
*   Caveat Evaluation (attenuation logic).
*   Redemption (proof-of-possession).
*   Expiry Checks.

## Relationship to Other Instantiations

Other implementations (EI₁, EI₂, ...) may use:
*   WireGuard or WebRTC for transport.
*   Solid Pods for storage.
*   Hardware Security Modules (HSMs) for key management.
*   VS Code or Browser extensions for UI.

This repository (`EI₀`) avoids those dependencies to remain a pure logic reference.

## Licensing

Licensed under the Apache License, Version 2.0.
