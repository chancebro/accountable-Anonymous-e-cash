<h1>Accountable Anonymous E-Cash — BLS12-381 Implementation</h1>

<p>
This repository contains two independent implementations of an Accountable Anonymous E-Cash system:
</p>

<ul>
  <li><b>Target Scheme</b> — baseline implementation based on the reference paper<br>
      → <code>main_target.cpp</code> + <code>target.cpp</code></li>
  <li><b>Our Improved Scheme</b> — supports selective tracing, BLS12-381, and optimized protocol operations<br>
      → <code>main_new.cpp</code> + <code>new.cpp</code></li>
</ul>

<p>Additional tools included:</p>

<ul>
  <li><b>Tracing Benchmark Tool</b> — forward/backward tracing performance evaluation<br>
      → <code>tracing_test.cpp</code> + <code>new.cpp</code></li>
  <li><b>BLS12-381 Curve Sanity Test</b> — verifies curve initialization and element sizes<br>
      → <code>test_bls381.cpp</code></li>
</ul>

<p>
All cryptographic operations rely on the MCL library (BLS12-381), which is bundled in this repository.
</p>

<hr>

<h2>📁 Project Structure</h2>

<pre>
.
├── mcl/                    # MCL cryptographic library (bundled)
│   ├── include/mcl/bn.hpp
│   ├── lib/libmcl.a
│   └── ...
│
├── new.cpp / new.h         # Our BLS12-381 optimized scheme
├── main_new.cpp            # Entry point for our implementation
│
├── target.cpp / target.h   # Target (reference) scheme
├── main_target.cpp         # Entry point for the target scheme
│
├── tracing_test.cpp        # Forward/Backward tracing benchmark tool
├── test_bls381.cpp         # Curve initialization and size test
│
├── Makefile
└── README.md
</pre>

<hr>

<h2>⚙️ Build Instructions</h2>

<p>This project is fully self-contained — <b>no external MCL installation required</b>.</p>

<h3>✔ Requirements</h3>
<ul>
  <li>g++ (C++17 or newer)</li>
  <li>SQLite3 (<code>libsqlite3-dev</code>)</li>
  <li>pthread</li>
  <li>MCL library already included under <code>/mcl</code></li>
</ul>

<h3>✔ Build Everything</h3>

<pre><code>make</code></pre>

<h3>✔ Generated Executables</h3>

<pre>
./main_target
./main_new
./tracing_test
./test_bls381
</pre>

<hr>

<h2>🚀 Running the Programs</h2>

<h3>1) Target Scheme (Baseline Implementation)</h3>

<p><code>./main_target</code></p>

<h4>📚 Target Scheme Reference</h4>
<p>
The target implementation (<code>main_target.cpp</code> + <code>target.cpp</code>) is based on:
</p>

<p><b>Dual-Anonymous Off-Line Electronic Cash for Mobile Payment</b><br>
Jianbing Ni, Man Ho Au, Wei Wu, Xiapu Luo, Xiaodong Lin, Xuemin Shen<br>
<i>IEEE Transactions on Mobile Computing (TMC), 2023</i><br>
DOI: 10.1109/TMC.2021.3135301
</p>

<p>This executable reproduces the baseline protocol from the reference paper.</p>

<hr>

<h3>2) Our Improved Scheme — Accountable Anonymity + Selective Tracing </h3>

<p><code>./main_new</code></p>

<p>Implements:</p>
<ul>
  <li>Account Establishment</li>
  <li>Withdraw</li>
  <li>Randomise</li>
  <li>Finalise</li>
  <li>Ledger insertion</li>
  <li>SPK1 / SPK2 (pk4) / SPK3 (pk6) generation & verification</li>
  <li>Full support for BLS12-381 (G1/G2/GT + Fp12 commitments)</li>
</ul>

<hr>

<h3>3) Tracing Performance Benchmark</h3>

<p><code>./tracing_test</code></p>

<p>Measures:</p>

<table border="1" cellpadding="4">
  <tr><th>Metric</th><th>Description</th></tr>
  <tr><td>Forward Tracing Time</td><td>Trace transactions forward in the chain</td></tr>
  <tr><td>Backward Tracing Time</td><td>Trace back to the source</td></tr>
  <tr><td>Total Time</td><td>Sum of forward + backward</td></tr>
  <tr><td>CSV Export</td><td>Automatically written to file</td></tr>
</table>

<hr>

<h3>4) BLS12-381 Curve Sanity Test</h3>

<p><code>./test_bls381</code></p>

<p>Verifies:</p>
<ul>
  <li>pairing(mcl::BLS12_381) initialization</li>
  <li>G1 = 48 bytes, G2 = 96 bytes, GT = 576 bytes</li>
  <li>hashing and curve functionality</li>
</ul>

<hr>

<h2>💾 Database Schema (Ledger Records)</h2>

<p>
The ledger records are stored in a single table <code>spk_bundle</code>.  
This schema is used for both <strong>Randomise</strong> and <strong>Finalise</strong> phases.  
Unused fields in a phase are stored as the literal string <code>"none"</code>.
</p>

<h3>Table Schema</h3>

<pre><code class="language-sql">
CREATE TABLE IF NOT EXISTS spk_bundle (
    Ts_num           INTEGER PRIMARY KEY AUTOINCREMENT,
    S                TEXT,
    D                TEXT,
    INFO             TEXT,
    R                TEXT,
    N                TEXT,
    M                TEXT,
    T                TEXT,
    backward_C1      TEXT,
    backward_C2      TEXT,
    bank_B           TEXT,
    forward_C1       TEXT,
    forward_C2       TEXT,
    userID_payer_C1  TEXT,
    userID_payer_C2  TEXT,
    userID_payee_C1  TEXT,
    userID_payee_C2  TEXT
);
</code></pre>

<h3>Indexes for Tracing & Double-Spending Detection</h3>

<pre><code class="language-sql">
CREATE INDEX IF NOT EXISTS idx_S      ON spk_bundle (S);
CREATE INDEX IF NOT EXISTS idx_T      ON spk_bundle (T);
CREATE INDEX IF NOT EXISTS idx_bank_B ON spk_bundle (bank_B);
CREATE INDEX IF NOT EXISTS idx_R      ON spk_bundle (R);
</code></pre>

<h3>User Table</h3>

<pre><code class="language-sql">
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    U  TEXT
);
</code></pre>

<h3>Field Descriptions</h3>

<table>
<tr><th>Column</th><th>Description</th></tr>

<tr><td><code>Ts_num</code></td><td>Auto-incremented logical transaction number</td></tr>
<tr><td><code>S</code></td><td>SPK1 proof element (used for double-spending detection)</td></tr>
<tr><td><code>D</code></td><td>SPK2 output associated with the coin/tracing state</td></tr>
<tr><td><code>INFO</code></td><td>Metadata for tracing (e.g., AML policy context)</td></tr>
<tr><td><code>R</code></td><td>Commitment representing the "new coin" after Randomise</td></tr>
<tr><td><code>N</code></td><td>Random nonce used in coin formation</td></tr>
<tr><td><code>M</code></td><td>Transaction message metadata</td></tr>
<tr><td><code>T</code></td><td>Tracing tag used in selective tracing</td></tr>

<tr><td><code>backward_C1</code></td><td>Backward ciphertext component 1 (Backward Tracing)</td></tr>
<tr><td><code>backward_C2</code></td><td>Backward ciphertext component 2</td></tr>

<tr><td><code>bank_B</code></td><td>Bank-side forward-tracing anchor (set to <code>"none"</code> during Finalise)</td></tr>
<tr><td><code>forward_C1</code></td><td>Forward ciphertext component 1</td></tr>
<tr><td><code>forward_C2</code></td><td>Forward ciphertext component 2</td></tr>

<tr><td><code>userID_payer_C1</code></td><td>Encrypted payer identity — part 1</td></tr>
<tr><td><code>userID_payer_C2</code></td><td>Encrypted payer identity — part 2</td></tr>
<tr><td><code>userID_payee_C1</code></td><td>Encrypted payee identity — part 1</td></tr>
<tr><td><code>userID_payee_C2</code></td><td>Encrypted payee identity — part 2</td></tr>

</table>

<h3>Phase-Specific Usage</h3>

<h4>🔷 Randomise Phase (new coin created)</h4>
<ul>
<li><code>R</code> stores the committed new coin.</li>
<li><code>bank_B</code>, <code>forward_C1</code>, <code>forward_C2</code> contain valid forward-tag fields.</li>
</ul>

<h4>🔷 Finalise Phase (coin consumed)</h4>
<ul>
<li>No new coin is generated.</li>
<li><code>bank_B</code>, <code>forward_C1</code>, <code>forward_C2</code> are stored as <code>"none"</code>.</li>
</ul>
<h2>📦 MCL Library Usage</h2>

<p>This repository includes a pre-built MCL library:</p>

<ul>
  <li><code>mcl/include/</code> — headers</li>
  <li><code>mcl/lib/libmcl.a</code> — static library</li>
</ul>

<p><b>No external installation is required.</b></p>

<p>You do NOT need:</p>
<ul>
  <li><code>brew install mcl</code></li>
  <li><code>apt install mcl</code></li>
  <li><code>git clone mcl</code></li>
</ul>

<p>Everything compiles with:</p>

<pre><code>make</code></pre>

<hr>

<h2>🧾 Notes</h2>

<ul>
  <li>All pairing operations use <b>BLS12-381</b> for strong 128-bit security.</li>
  <li>Group sizes: G1 = 48 bytes, G2 = 96 bytes, GT = 576 bytes.</li>
  <li>SPK1 / SPK2(pk4) / SPK3(pk6) are fully implemented for selective tracing.</li>
  <li>Tracing benchmark is optimized for long chains and high-volume evaluation.</li>
</ul>

<hr>

<h2>👤 Author</h2>

<p><b>Chanhyeong Cho</b><br>
Korea University — PET Lab<br>
Research Interests: Anonymous Payment, Accountable Privacy, E-Cash, AML/CTF-Aware Cryptography
</p>
