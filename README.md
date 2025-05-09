# Plonk IOP in Rust

## 🚀 What is this?

This project is a **Rust implementation of the Plonk IOP** protocol, including both the **prover** and **verifier** for a given arithmetic circuit. The implementation is designed from the ground up with a clear educational focus, while laying the groundwork for future performance optimizations.

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

### 🔧 Plonk IOP Protocol (WIP)

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

---

## 🛠️ In Progress

* 🔧 Full Plonk IOP integration with a concrete example circuit
* 🔧 Selector polynomials & constraint systems
* 🔧 Parallelized FFTs and multiexponentiation

---

## 📁 Repository Layout

```
src/
├── common/                  # Shared helpers (e.g. pairing accessors)
├── kzg/                     # KZG commitment logic
├── polynomials/             # Polynomial operations
├── protocols/               # Poly-IOP gadgets (e.g., equality, sum-check)
├── plonk/                   # Plonk IOP system (WIP)
└── bin/
    ├── prover.rs            # Executable for the prover
    └── verifier.rs          # Executable for the verifier

tests/
├── bls12_381_tests.rs       # Tests for field operations
├── ec_tests.rs              # Tests for elliptic curve group and pairing ops
├── kzg_tests.rs             # Tests for commitment, opening, and verification
├── protocols_tests.rs       # Tests for poly-IOP gadgets like permutation checks
└── polynomials_tests.rs     # Tests for univariate polynomial evaluation and logic
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

## 🏃 Running the Prover and Verifier

This project includes two binaries located in `src/bin/`:

* `prover.rs` — runs the prover protocol
* `verifier.rs` — runs the verifier protocol

To run them:

```bash
cargo run --bin prover
cargo run --bin verifier
```

You can also list all available binaries with:

```bash
cargo run --bin
```

---

## 📚 Learnings & Insights

* Evaluation at random verifier-chosen points is sufficient for prescribed permutation checks.
* Evaluation-based polynomial equality is a clean and modular method for enforcing constraints.
* Composing IOP layers around commitments enables flexible circuit representations.

---

## 🤝 Contributing

This project is a work-in-progress, originally built for learning and prototyping. Feedback, pull requests, and ideas are welcome!

If you're working on a ZK protocol, curious about Plonk internals, or building custom circuits, feel free to reach out or fork and hack along.

---

## 📜 License

This project is dual-licensed under **MIT** and **Apache 2.0**. You can choose either license when using or contributing.

This approach is widely adopted in the Rust ecosystem and balances simplicity with flexibility — allowing you to integrate the code in both permissive and Apache-compatible projects.
