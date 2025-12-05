#include <iostream>
#include "new.h"
#include <chrono>  // 이 헤더 추가
#include <fstream>
#include <random>
#include <vector>

// BLS12-381용 설정 헤더 (반드시 bn.hpp보다 먼저)
#include <mcl/bn_c384_256.h>
#include <mcl/bn.hpp>




auto checkSetStr = [](auto& field, const char* valStr, const std::string& name, int base = 16) {
    try {
        using T = std::decay_t<decltype(field)>;
        if constexpr (std::is_same_v<T, mcl::bn::Fp12>) {
            std::stringstream ss(valStr);
            ss >> field;
            if (ss.fail()) throw cybozu::Exception("Fp12 load failed");
        } else {
            field.setStr(valStr, base);
        }
    } catch (const cybozu::Exception& e) {
        std::cerr << "❌ " << name << " setStr 실패\n값: " << valStr << "\n";
        std::cerr << "예외 메시지: " << e.what() << "\n";
        return false;
    }
    return true;
};
void measure_account_est() {
    std::cout << "[account_est] Measurement started...\n";
    if (!initDatabase(db)) return;
    initPairing(mcl::BLS12_381);  // pairing 초기화

    // Generator 및 pairing 초기화
    G1 g, g0, g1, gE, h, h0, h1, h2, hE, ht;
    G2 g_G2, h_G2;
    Fp12 G, GE, H, H1;

    setupH_Generators(h, h0, h1, h2, hE, ht, h_G2);
    setupG_Generators(g, g0, g1, gE, g_G2);

    // 개인키 값 설정
    alpha = 1;
    beta = 2;
    x_GE = 3;
    x_h = 4;

    G2::mul(W, g_G2, alpha);
    G2::mul(X, h_G2, beta);

    pairing(G, g, g_G2);
    pairing(GE, g1, g_G2);
    pairing(H, h, h_G2);
    pairing(H1, h1, h_G2);

    // 사용자 설정
    User user1;
    user1.u.setByCSPRNG();
    Fp12::pow(user1.U, G, user1.u); // U 생성

    // 공개 파라미터 (P, Q) 계산
    Fp12::pow(P, GE, x_GE);
    G1::mul(Q, hE, x_h);

    // 측정 파일 생성
    std::ofstream csv("account_est_timing_proposal.csv");
    csv << "Iteration,UserSide1_ns,BankSide_ns,UserSide2_ns\n";

    for (int i = 0; i < 10000; ++i) {
        long long t1 = 0, t2 = 0, t3 = 0;

        bool success = account_est_time(user1, g, g0, g1, g_G2, G, t1, t2, t3);
        if (!success) {
            std::cerr << "Iteration " << i << ": account_est failed\n";
        }

        csv << i << "," << t1 << "," << t2 << "," << t3 << "\n";
    }

    csv.close();
    sqlite3_close(db);
    std::cout << "[account_est] Measurement completed.\n";
}
void measure_withdraw_coin() {
    std::cout << "[withdraw_coin] Measurement started...\n";
    if (!initDatabase(db)) return;
    initPairing(mcl::BLS12_381);  // pairing 초기화

    // Generator 및 pairing 초기화
    G1 g, g0, g1, gE, h, h0, h1, h2, hE, ht;
    G2 g_G2, h_G2;
    Fp12 G, GE, H, H1;

    setupH_Generators(h, h0, h1, h2, hE, ht, h_G2);
    setupG_Generators(g, g0, g1, gE, g_G2);

    // 개인키 값 설정
    alpha = 1;
    beta  = 2;
    x_GE  = 3;
    x_h   = 4;

    G2::mul(W, g_G2, alpha);
    G2::mul(X, h_G2, beta);

    pairing(G, g, g_G2);
    pairing(GE, g1, g_G2);
    pairing(H, h, h_G2);
    pairing(H1, h1, h_G2);

    // 사용자 생성 및 키 초기화
    User user1, user2;
    user1.u.setByCSPRNG();
    user2.u.setByCSPRNG();

    Fp12::pow(user1.U, G, user1.u);
    Fp12::pow(user2.U, G, user2.u);

    Fp12::pow(P, GE, x_GE);
    G1::mul(Q, hE, x_h);

    // 계정 생성
    if (account_est(user1, g, g0, g1, g_G2, G)) {
        std::cout << "User 1 account created with signature A = " << user1.A.getStr(16) << std::endl;
    } else {
        std::cout << "Account establishment failed." << std::endl;
    }

    if (account_est(user2, g, g0, g1, g_G2, G)) {
        std::cout << "User 2 account created with signature A = " << user2.A.getStr(16) << std::endl;
    } else {
        std::cout << "Account establishment failed." << std::endl;
    }

    // 측정 시작
    std::ofstream csv("withdraw_coin_timing_proposal.csv");
    csv << "Iteration,UserSide1_ns,BankSide_ns,UserSide2_ns\n";

    for (int i = 0; i < 10000; ++i) {
        long long user1_t = 0, bank_t = 0, user2_t = 0;

        bool success = withdraw_coin_time(user1,
                                          h, h0, h1, h2, h_G2,
                                          G,
                                          user1_t, bank_t, user2_t);

        if (!success) {
            std::cerr << "Iteration " << i << ": withdraw_coin failed\n";
        }

        csv << i << "," << user1_t << "," << bank_t << "," << user2_t << "\n";
    }

    csv.close();
    sqlite3_close(db);
    std::cout << "[withdraw_coin] Measurement completed.\n";
}
void measure_payment() {
    std::cout << "[payment] Measurement started...\n";
    if (!initDatabase(db)) return;
    initPairing(mcl::BLS12_381); // pairing 초기화

    // Generator 및 pairing 초기화
    G1 g, g0, g1, gE, h, h0, h1, h2, hE, ht;
    G2 g_G2, h_G2;
    Fp12 G, GE, H, H1;

    setupH_Generators(h, h0, h1, h2, hE, ht, h_G2);
    setupG_Generators(g, g0, g1, gE, g_G2);

    // 개인키 값 설정
    alpha = 1;
    beta  = 2;
    x_GE  = 3;
    x_h   = 4;

    G2::mul(W, g_G2, alpha);
    G2::mul(X, h_G2, beta);

    pairing(G, g, g_G2);
    pairing(GE, g1, g_G2);
    pairing(H, h, h_G2);
    pairing(H1, h1, h_G2);

    // 사용자 생성 및 키 초기화
    User user1, user2;
    user1.u.setByCSPRNG();
    user2.u.setByCSPRNG();

    Fp12::pow(user1.U, G, user1.u); // generate User identifier U
    Fp12::pow(user2.U, G, user2.u);

    Fp12::pow(P, GE, x_GE);
    G1::mul(Q, hE, x_h);

    // account setup
    if (account_est(user1, g, g0, g1, g_G2, G)) {
        std::cout << "User 1 account created with signature A = " << user1.A.getStr(16) << std::endl;
    } else {
        std::cout << "Account establishment failed." << std::endl;
    }

    if (account_est(user2, g, g0, g1, g_G2, G)) {
        std::cout << "User 2 account created with signature A = " << user2.A.getStr(16) << std::endl;
    } else {
        std::cout << "Account establishment failed." << std::endl;
    }

    // coin withdrawal
    if (withdraw_coin(user1, h, h0, h1, h2, h_G2, G)) {
        std::cout << "User 1 Coin created with signature B = " << user1.B.getStr(16) << std::endl;
    } else {
        std::cout << "Coin withdrawal failed." << std::endl;
    }

    // 시간 측정 루프
    std::ofstream csv("payment_proposal.csv");
    csv << "Iteration,Payee1_ns,Payer_ns,Payee2_ns\n";

    for (int i = 0; i < 10000; ++i) {
        long long t1 = 0, t2 = 0, t3 = 0;

        bool success = Payment_time(user1, user2,
                                    g, g0, g1, gE, g_G2, G, GE,
                                    h, h0, h1, h2, hE, ht, h_G2,
                                    H, H1,
                                    t1, t2, t3);

        if (!success) {
            std::cerr << "Iteration " << i << ": Payment failed\n";
        }

        csv << i << "," << t1 << "," << t2 << "," << t3 << "\n";
    }

    csv.close();
    sqlite3_close(db);
    std::cout << "[payment] Measurement completed.\n";
}
void measure_randomise() {
    std::cout << "[randomise] Measurement started...\n";
    if (!initDatabase(db)) return;
    initPairing(mcl::BLS12_381);  // pairing 초기화

    G1 g,g0,g1,gE,h,h0,h1,h2,hE,ht;
    G2 g_G2,h_G2;
    Fp12 G, GE, H, H1;

    setupH_Generators(h, h0, h1, h2, hE, ht, h_G2);
    setupG_Generators(g, g0, g1, gE, g_G2);

    // 개인키 값 초기화
    alpha = 1;
    beta = 2;
    x_GE = 3;
    x_h  = 4;

    G2::mul(W, g_G2, alpha);
    G2::mul(X, h_G2, beta);

    pairing(G, g, g_G2);
    pairing(GE, g1, g_G2);
    pairing(H, h, h_G2);
    pairing(H1, h1, h_G2);

    User user1, user2;

    user1.u.setByCSPRNG();
    user2.u.setByCSPRNG();

    std::string INFO;

    Fp12::pow(user1.U, G, user1.u);
    Fp12::pow(user2.U, G, user2.u);

    Fp12::pow(P, GE, x_GE);
    G1::mul(Q, hE, x_h);

    if (account_est(user1, g, g0, g1, g_G2, G)) {
        std::cout << "User 1 account created with signature A = " << user1.A.getStr(16) << std::endl;
    } else {
        std::cout << "Account establishment failed." << std::endl;
    }

    if (account_est(user2, g, g0, g1, g_G2, G)) {
        std::cout << "User 2 account created with signature A = " << user2.A.getStr(16) << std::endl;
    } else {
        std::cout << "Account establishment failed." << std::endl;
    }

    if (withdraw_coin(user1, h, h0, h1, h2, h_G2, G)) {
        std::cout << "User 1 Coin created with signature B = " << user1.B.getStr(16) << std::endl;
    } else {
        std::cout << "Coin withdrawal failed." << std::endl;
    }

    if (Payment(user1, user2, g, g0, g1, gE, g_G2, G, GE,
                h, h0, h1, h2, hE, ht, h_G2, H, H1)) {
        std::cout << "User 1 payment to User 2\n";
    } else {
        std::cout << "Payment failed.\n";
    }

    std::ofstream csv("randomise_timing_proposal.csv");
    csv << "Iteration,Payee1_ns,Bank1_ns,Payee2_ns,Bank2_ns,Payee3_ns,Bank3_ns\n";

    for (int i = 0; i < 10000; ++i) {
        long long t1, t2, t3, t4, t5, t6;
        bool success = randomise_time(user2,
                                      g, g0, g1, g_G2, G, GE,
                                      h, h0, h1, h2, hE, ht, h_G2,
                                      H, H1,
                                      t1, t2, t3, t4, t5, t6);

        if (!success) std::cerr << "Randomise failed on iteration " << i << "\n";
        csv << i << "," << t1 << "," << t2 << "," << t3 << "," << t4 << "," << t5 << "," << t6 << "\n";
    }

    csv.close();
    sqlite3_close(db);
    std::cout << "[randomise] Measurement completed.\n";
}
void measure_finalise() {
    std::cout << "[finalise] Measurement started...\n";
    if (!initDatabase(db)) return;
    initPairing(mcl::BLS12_381); // pairing 초기화

    // Generator 및 pairing 초기화
    G1 g, g0, g1, gE, h, h0, h1, h2, hE, ht;
    G2 g_G2, h_G2;
    Fp12 G, GE, H, H1;

    setupH_Generators(h, h0, h1, h2, hE, ht, h_G2);
    setupG_Generators(g, g0, g1, gE, g_G2);

    // 개인키 값 설정
    alpha = 1;
    beta  = 2;
    x_GE  = 3;
    x_h   = 4;

    G2::mul(W, g_G2, alpha);
    G2::mul(X, h_G2, beta);

    pairing(G, g, g_G2);
    pairing(GE, g1, g_G2);
    pairing(H, h, h_G2);
    pairing(H1, h1, h_G2);

    // 사용자 생성
    User user1, user2;
    user1.u.setByCSPRNG();
    user2.u.setByCSPRNG();

    Fp12::pow(user1.U, G, user1.u);
    Fp12::pow(user2.U, G, user2.u);

    Fp12::pow(P, GE, x_GE);
    G1::mul(Q, hE, x_h);

    // 계정 생성
    if (account_est(user1, g, g0, g1, g_G2, G)) {
        std::cout << "User 1 account created with signature A = " << user1.A.getStr(16) << std::endl;
    } else {
        std::cout << "Account establishment failed." << std::endl;
    }

    if (account_est(user2, g, g0, g1, g_G2, G)) {
        std::cout << "User 2 account created with signature A = " << user2.A.getStr(16) << std::endl;
    } else {
        std::cout << "Account establishment failed." << std::endl;
    }

    // 코인 발급
    if (withdraw_coin(user1, h, h0, h1, h2, h_G2, G)) {
        std::cout << "User 1 Coin created with signature B = " << user1.B.getStr(16) << std::endl;
    } else {
        std::cout << "Coin withdrawal failed." << std::endl;
    }

    // 결제
    if (Payment(user1, user2,
                g, g0, g1, gE, g_G2, G, GE,
                h, h0, h1, h2, hE, ht, h_G2, H, H1)) {
        std::cout << "User 1 payment to User 2\n";
    } else {
        std::cout << "Payment failed.\n";
    }

    // Finalise 성능 측정
    std::ofstream csv("finalise_timing_proposal.csv");
    csv << "Iteration,Payee_ns,Bank_ns\n";

    for (int i = 0; i < 10000; ++i) {
        long long payee_t = 0, bank_t = 0;

        bool success = finalise_time(user2,
                                     g, g0, g1, g_G2, G, GE,
                                     h, h0, h1, h2, hE, ht, h_G2,
                                     H, H1,
                                     payee_t, bank_t);
        if (!success) {
            std::cerr << "Iteration " << i << ": finalise failed\n";
        }

        csv << i << "," << payee_t << "," << bank_t << "\n";
    }
    csv.close();
    sqlite3_close(db);
    std::cout << "[finalise] Measurement completed.\n";
}

// [헬퍼 함수] 객체의 직렬화(Serialize) 크기 측정
template <typename T>
size_t getRawSize(const T& obj) {
    char buf[2048]; // 충분히 큰 버퍼
    return obj.serialize(buf, sizeof(buf));
}

int main() {
    if (!initDatabase(db)) return -1;

    // 1. 초기화 (인자 없이 호출 -> 기본 설정 확인용)
    // 주의: Makefile이나 컴파일 옵션에서 MCL_USE_BLS12_381=1 등이 설정되어 있어야 함
    // 코드 내에서 강제하려면 initPairing(mcl::BLS12_381); 을 권장
    //mclBn_init(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    mcl::bn::initPairing(mcl::BLS12_381);


    // Generator 초기화
    G1 g, g0, g1, gE, h, h0, h1, h2, hE, ht;
    G2 g_G2, h_G2;
    Fp12 G, GE, H, H1;

    setupH_Generators(h, h0, h1, h2, hE, ht, h_G2);
    setupG_Generators(g, g0, g1, gE, g_G2);

    // 개인키 값 초기화
    alpha = 1;
    beta  = 2;
    x_GE  = 3;
    x_h   = 4;

    G2::mul(W, g_G2, alpha);
    G2::mul(X, h_G2, beta);

    pairing(G, g, g_G2);
    pairing(GE, g1, g_G2);
    pairing(H, h, h_G2);
    pairing(H1, h1, h_G2);

    Fp12::pow(P, GE, x_GE);
    G1::mul(Q, hE, x_h);

// === 체인 기반 트랜잭션 생성 ===
    const int TARGET_TX_COUNT = 5000;

    std::random_device rd;
    std::mt19937 gen(rd());

    // 체인 길이 비율: {2~5}:50%, {6~10}:30%, {11~20}:20%
    std::discrete_distribution<> weight_dist({50, 30, 20});
    std::uniform_int_distribution<> short_len(2, 5);
    std::uniform_int_distribution<> mid_len(6, 10);
    std::uniform_int_distribution<> long_len(11, 20);

    int tx_count = 0;
    int chain_id = 0;
    int global_user_id = 1; // 유일한 사용자 ID 관리

    while (tx_count < TARGET_TX_COUNT) {
        int chain_len = 0;
        int len_type = weight_dist(gen);
        switch (len_type) {
            case 0: chain_len = short_len(gen); break;
            case 1: chain_len = mid_len(gen); break;
            case 2: chain_len = long_len(gen); break;
        }

        if (tx_count + chain_len > TARGET_TX_COUNT) break;

        std::vector<User> users(chain_len + 1);
        for (auto& user : users) {
            user.u.setByCSPRNG();
            Fp12::pow(user.U, G, user.u);

            if (!account_est(user, g, g0, g1, g_G2, G)) {
                std::cerr << "❌ Account_est 실패\n";
                return -1;
            }

            if (!insertUserU(db, global_user_id++, user.U)) {
                std::cerr << "❌ insertUserU 실패\n";
                return -1;
            }
        }

        // 첫 사용자: 새로운 코인 발행
        if (!withdraw_coin(users[0], h, h0, h1, h2, h_G2, G)) {
            std::cerr << "❌ Withdraw 실패 on chain " << chain_id << "\n";
            continue;
        }

        bool chain_success = true;
        for (int i = 0; i < chain_len - 1; ++i) {
            if (!Payment(users[i], users[i+1], g, g0, g1, gE, g_G2, G, GE,
                         h, h0, h1, h2, hE, ht, h_G2, H, H1)) {
                std::cerr << "❌ Payment 실패 in chain " << chain_id << " step " << i << "\n";
                chain_success = false;
                break;
            }

            if (!randomise(users[i+1], g, g0, g1, g_G2, G, GE,
                           h, h0, h1, h2, hE, ht, h_G2, H, H1)) {
                std::cerr << "❌ Randomise 실패 in chain " << chain_id << " step " << i << "\n";
                chain_success = false;
                break;
            }
        }

        // 마지막 payment → finalise
        if (chain_success &&
            Payment(users[chain_len - 1], users[chain_len], g, g0, g1, gE, g_G2, G, GE,
                    h, h0, h1, h2, hE, ht, h_G2, H, H1)) {

            if (finalise(users[chain_len], g, g0, g1, g_G2, G, GE,
                         h, h0, h1, h2, hE, ht, h_G2, H, H1)) {
                std::cout << "✅ Chain " << chain_id << " completed (length: " << chain_len << ")\n";
                tx_count += chain_len;
            } else {
                std::cerr << "❌ Finalise 실패 in chain " << chain_id << "\n";
            }
        }

        chain_id++;
    }

    std::cout << "\n===== 전체 체인 생성 완료 (" << tx_count << " 트랜잭션) =====\n";
    
    return 0;
}