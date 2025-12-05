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

<h3>2) Our Improved Scheme — Selective Tracing + BLS12-381</h3>

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

<p>Ledger records differ depending on whether a coin is <b>Randomised</b> or <b>Finalised</b>.</p>

<h3>🔷 Randomise Phase (new coin created)</h3>

<table border="1" cellpadding="4">
<tr><th>Column</th><th>Description</th></tr>
<tr><td>S</td><td>SPK1 pairing proof</td></tr>
<tr><td>D</td><td>SPK2 output</td></tr>
<tr><td>INFO</td><td>tracing metadata</td></tr>
<tr><td>N</td><td>coin randomness</td></tr>
<tr><td>M</td><td>message metadata</td></tr>
<tr><td>T</td><td>tracing tag</td></tr>
<tr><td>userID_payer_C1</td><td>encrypted payer ID (part 1)</td></tr>
<tr><td>userID_payer_C2</td><td>encrypted payer ID (part 2)</td></tr>
<tr><td>userID_payee_C1</td><td>encrypted payee ID (part 1)</td></tr>
<tr><td>userID_payee_C2</td><td>encrypted payee ID (part 2)</td></tr>
<tr><td>new_coin</td><td>commitment of newly generated coin</td></tr>
</table>

<h3>🔷 Finalise Phase (coin consumed)</h3>

<p><code>new_coin = "none"</code></p>

<table border="1" cellpadding="4">
<tr><th>Column</th><th>Description</th></tr>
<tr><td>S</td><td>SPK1 proof</td></tr>
<tr><td>D</td><td>SPK2 proof</td></tr>
<tr><td>INFO</td><td>metadata</td></tr>
<tr><td>N</td><td>randomness</td></tr>
<tr><td>M</td><td>message</td></tr>
<tr><td>T</td><td>tracing tag</td></tr>
<tr><td>userID_payer_C1</td><td>payer ciphertext (part 1)</td></tr>
<tr><td>userID_payer_C2</td><td>payer ciphertext (part 2)</td></tr>
<tr><td>userID_payee_C1</td><td>payee ciphertext (part 1)</td></tr>
<tr><td>userID_payee_C2</td><td>payee ciphertext (part 2)</td></tr>
<tr><td>new_coin</td><td>"none"</td></tr>
</table>

<hr>

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
