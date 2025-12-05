Accountable Anonymous E-Cash — BLS12-381 Implementation

This repository contains two independent implementations of an Accountable Anonymous E-Cash system:

Target Scheme — baseline implementation based on the reference paper
→ main_target.cpp + target.cpp

Our Improved Scheme — supports selective tracing, BLS12-381, and optimized protocol operations
→ main_new.cpp + new.cpp

Additional tools included:

Tracing Benchmark Tool — forward/backward tracing performance evaluation
→ tracing_test.cpp + new.cpp

BLS12-381 Curve Sanity Test — verifies curve initialization and element sizes
→ test_bls381.cpp

All cryptographic operations rely on the MCL library (BLS12-381), which is bundled in this repository.

## 📁 Project Structure
.
📁 mcl/                      
│   ├── include/mcl/bn.hpp
│   ├── lib/libmcl.a
│   └── ...
│
📄 new.cpp / new.h           
📄 main_new.cpp              
│
📄 target.cpp / target.h     
📄 main_target.cpp           
│
📄 tracing_test.cpp          
📄 test_bls381.cpp           
│
🛠️ Makefile
📝 README.md


⚙️ Build Instructions

This project is fully self-contained — no external MCL installation required.

✔ Requirements

g++ (C++17 or newer)

SQLite3 (libsqlite3-dev)

pthread

MCL library already included under /mcl

✔ Build Everything
make

✔ Generated Executables
./main_target
./main_new
./tracing_test
./test_bls381

🚀 Running the Programs
1) Target Scheme (Baseline Implementation)
./main_target


Reproduces the protocol defined in the reference paper.

2) Our Scheme — Selective Tracing + BLS12-381
./main_new


Implements:

Account Establishment

Withdraw

Randomise

Finalise

Ledger insertion

SPK1, SPK2 (pk4), SPK3 (pk6) proof generation & verification

Full BLS12-381 support (G1/G2/GT, Fp12-based commitments)

3) Tracing Performance Benchmark
./tracing_test


Measures:

Metric	Description
Forward Tracing Time	Tracing transactions forward in the chain
Backward Tracing Time	Tracing backward to the source
Total Time	Sum of both directions
CSV Export	All results automatically written to file
4) BLS12-381 Curve Sanity Test
./test_bls381


Verifies:

pairing initialization

correct group element sizes (G1 = 48 bytes, GT = 576 bytes)

curve availability and hashing

💾 Database Schema (Ledger Records)

Ledger records differ depending on whether a coin is Randomised or Finalised.

🔷 Randomise Phase (new coin created)
Column	Description
S	SPK1 pairing proof
D	SPK2 output
INFO	tracing-related metadata
N	randomness used in the coin
M	message metadata
T	tracing tag
userID_payer_C1	encrypted payer ID (part 1)
userID_payer_C2	encrypted payer ID (part 2)
userID_payee_C1	encrypted payee ID (part 1)
userID_payee_C2	encrypted payee ID (part 2)
new_coin	commitment of newly generated coin
🔷 Finalise Phase (coin consumed)

new_coin = "none" because no new coin is produced.

Column	Description
S	SPK1 proof
D	SPK2 proof
INFO	metadata
N	randomness
M	message
T	tracing tag
userID_payer_C1	payer ciphertext (part 1)
userID_payer_C2	payer ciphertext (part 2)
userID_payee_C1	payee ciphertext (part 1)
userID_payee_C2	payee ciphertext (part 2)
new_coin	"none"
📦 MCL Library Usage

This repository includes a pre-built MCL library.

Included:

mcl/include/ — headers

mcl/lib/libmcl.a — static library

❌ No external installation required

You do not need:

brew install mcl
apt install mcl
git clone mcl

✔ Everything compiles immediately with:
make

🧾 Notes

All pairing operations use BLS12-381, providing strong 128-bit security.

Group sizes:

G1 = 48 bytes, G2 = 96 bytes, GT = 576 bytes

SPK1 / SPK2(pk4) / SPK3(pk6) are fully implemented for selective tracing.

Ledger stores only minimal information needed for accountable anonymity.

Tracing benchmark is optimized for large-scale evaluation.

👤 Author

Chanhyeong Cho
Korea University — PET Lab
Research Interests: Anonymous Payment, Accountable Privacy, E-Cash, AML/CTF-Aware Cryptography

