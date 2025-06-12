# Plonk IOP in Rust

## 🚀 What is this?

This project is a **Rust implementation of the Plonk IOP** protocol, including both the **setup**, **prover** and **verifier** for a given arithmetic circuit. The implementation is designed from the ground up with a clear educational focus, while laying the groundwork for future performance optimizations.

---

## 🎯 Why build this?

This project was developed to:

* **Understand Plonk deeply** by re-implementing each layer from scratch,
* **Demystify the stack** involved in a Plonk proof system — from field arithmetic to polynomial IOPs,
* **Experiment with optimizations** such as parallelism in FFTs and batched commitments.

It serves as both a **learning tool** and a **prototype** for efficient ZK proof systems in Rust.

---

## 🧱 High-Level Architecture

The project is organized into modular components that reflect the natural layering of a Plonk-style proof system.

### 🔢 Arithmetic Primitives

* **Finite Field Arithmetic:**

  * Based on BLS12-381 scalar field.
  * Built using `ark-ff` for field operations.

* **Elliptic Curve and Pairing Arithmetic:**

  * Uses `ark-ec` for group and pairing operations over BLS12-381.

### 📦 Polynomial Commitment Scheme (KZG)

* Implemented using univariate polynomials.
* Functionalities:

  * **Setup:** Generate SRS (structured reference string).
  * **Commit:** Compute a polynomial commitment.
  * **Evaluate:** Prove the evaluation of a committed polynomial at a point.
  * **Verify:** Verify the evaluation proof.

### 🧪 Poly-IOP Gadgets

Protocols for proving properties of committed polynomials:

* **Equality Check:** Ensure two committed polynomials are equal.
* **Zero Test:** Show that a polynomial vanishes on a domain Ω.
* **Sum Check:** Prove that the sum over Ω equals 0.
* **Product Check:** Prove that the product over Ω equals 1.
* **Product over Rational Functions:** Generalization to f/g.
* **Permutation Check:** Prove f(Ω) is a permutation of g(Ω).
* **Prescribed Permutation Check:** Prove f(Ω) = g(W(Ω)) for known permutation W.

### 🔧 Plonk IOP Protocol

An IOP-based implementation of the Plonk protocol for a **simple arithmetic circuit**.
Steps:

1. **Encode the computation trace** as a polynomial T(x).
2. **Prove correctness of computation**:

   * Inputs are encoded correctly.
   * Gates are applied correctly.
   * Wiring between gates is respected.
   * Output matches expected result.

---

## ✅ Features Implemented

* ✅ Field arithmetic over BLS12-381 using `ark-ff`
* ✅ Elliptic curve and pairing arithmetic using `ark-ec`
* ✅ KZG polynomial commitment scheme
* ✅ Poly-IOP gadgets
* ✅ Full Plonk IOP pipeline implemented and tested on a hard-coded example circuit
* All core components of the Plonk IOP have been completed and tested against a hard-coded example circuit.

---

## 🛠️ In Progress

The next step is to generalize the implementation to support arbitrary circuits, specified externally (e.g., via a JSON file). This will allow the system to generate and verify Plonk proofs for any user-defined circuit rather than relying on a hard-coded example.

---

## 🏃 Running the Full Plonk IOP Pipeline

The project includes five executables, each corresponding to a step in the Plonk proving and verification workflow:

1. **Global Setup:** Generates universal parameters (SRS) for the system.
   ```bash
   cargo run --bin setup_global_params
   ```

2. **Proving Key Setup:** Generates the proving key specific to the target circuit, it will be used by the prover.
   ```bash
   cargo run --bin setup_proving_key
   ```

3. **Verification Key Setup:** Generates the verification key specific to the target circuit, it will be used by the verifier.
   ```bash
   cargo run --bin setup_verification_key
   ```

4. **Proof Generation (Prover):** Executes the Plonk IOP prover algorithm.
   ```bash
   cargo run --bin prover
   ```

5. **Proof Verification (Verifier):** Runs the verifier to check the correctness of the proof.
   ```bash
   cargo run --bin verifier
   ```

Each binary performs one step of the end-to-end protocol and may read/write intermediate files such as proving/verification keys and the generated proof.

---

## 📁 Repository Layout

```
src/
├── bin/                             # Entrypoint binaries for setup, proving, and verification
│   ├── prover.rs                    # Loads inputs and runs the proving logic
│   ├── verifier.rs                  # Loads inputs and runs the verifying logic
│   ├── setup_global_params/         # Global parameter setup (SRS)
│   ├── setup_proving_key/           # Proving key generation
│   └── setup_verification_key/      # Verification key generation
├── common/                          # Core shared modules for Plonk IOP
│   ├── kzg.rs                       # KZG commitment logic
│   ├── mod.rs
│   ├── polynomials.rs               # Polynomial data structures and operations
│   ├── proof.rs                     # Proof data structures
│   ├── protocols.rs                 # Poly-IOP gadgets and Plonk IOP logic
│   └── utils.rs                     # Common utilities (e.g. pairing helpers)
├── prover/                          # Prover-side Plonk IOP implementation
│   ├── mod.rs
│   └── part*.rs                     # Modularized prover steps
├── verifier/                        # Verifier-side Plonk IOP implementation
│   ├── mod.rs
│   └── part*.rs                     # Modularized verifier steps

tests/
├── ec_tests.rs              # Tests for elliptic curve group and pairing ops
├── field_tests.rs           # Tests for field operations
├── kzg_tests.rs             # Tests for commitment, opening, and verification
├── protocols_tests.rs       # Tests for poly-IOP gadgets like permutation checks
├── polynomials_tests.rs     # Tests for univariate polynomial evaluation and logic
└── utils_tests.rs           # Tests for helpers functions
```

---

## 🧪 Testing Strategy

All core components are covered by a set of well-structured unit and integration tests located in `tests/` and inline module tests. Current test coverage includes:

* ✅ Field and polynomial arithmetic validation
* ✅ KZG commitment lifecycle (setup, commit, open, verify)
* ✅ Evaluation-based Poly-IOP protocols (e.g., permutation checks, sum checks)
* ✅ Protocol end-to-end checks for arithmetic constraints

Each module includes assertions to validate soundness and internal consistency. The project prioritizes transparency and reproducibility through thorough testing.

To run all tests:

```bash
cargo test
```

To run a specific test file:

```bash
cargo test --test kzg_tests
```

---

## 🤝 Contributing

This project is a work-in-progress, originally built for learning and prototyping. Feedback, pull requests, and ideas are welcome!

If you're working on a ZK protocol, curious about Plonk internals, or building custom circuits, feel free to reach out or fork and hack along.

---

## 📜 License

This project is dual-licensed under **MIT** and **Apache 2.0**. You can choose either license when using or contributing.

This approach is widely adopted in the Rust ecosystem and balances simplicity with flexibility — allowing you to integrate the code in both permissive and Apache-compatible projects.
