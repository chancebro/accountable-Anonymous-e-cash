#include <iostream>
#include <sstream>
#include <sqlite3.h>
#include "new.h"
#include <chrono>
#include <sqlite3.h>
#include <fstream> // ← 이 줄이 없으면 오류 발생
#include <mcl/bn.hpp>

using namespace mcl::bn;
using namespace std;
using namespace std::chrono;

int forwardTracing(sqlite3* db, int start_ts_num) {
    Fp12 S, userID_C1_payer, userID_C2_payer, userID_C1_payee, userID_C2_payee;
    G1 T, backward_C1, backward_C2, forward_C1, forward_C2, bank_B;

    while (start_ts_num != -1) {
        const char* sql_template = "SELECT S, T, backward_C1, backward_C2, bank_B, forward_C1, forward_C2, "
                                   "userID_payer_C1, userID_payer_C2, userID_payee_C1, userID_payee_C2 "
                                   "FROM spk_bundle WHERE Ts_num = ?;";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql_template, -1, &stmt, nullptr) != SQLITE_OK) return -1;
        sqlite3_bind_int(stmt, 1, start_ts_num);

        bool finalised = false;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* bank_b_raw = (const char*)sqlite3_column_text(stmt, 4);
            const char* fwd1_raw = (const char*)sqlite3_column_text(stmt, 5);
            const char* fwd2_raw = (const char*)sqlite3_column_text(stmt, 6);

            if (!bank_b_raw || string(bank_b_raw) == "none") finalised = true;

            try {
                stringstream ssS((const char*)sqlite3_column_text(stmt, 0)); ssS >> S;
                T.setStr((const char*)sqlite3_column_text(stmt, 1), 16);
                backward_C1.setStr((const char*)sqlite3_column_text(stmt, 2), 16);
                backward_C2.setStr((const char*)sqlite3_column_text(stmt, 3), 16);
                if (!finalised) {
                    bank_B.setStr(bank_b_raw, 16);
                    forward_C1.setStr(fwd1_raw, 16);
                    forward_C2.setStr(fwd2_raw, 16);
                }
                stringstream((const char*)sqlite3_column_text(stmt, 7)) >> userID_C1_payer;
                stringstream((const char*)sqlite3_column_text(stmt, 8)) >> userID_C2_payer;
                stringstream((const char*)sqlite3_column_text(stmt, 9)) >> userID_C1_payee;
                stringstream((const char*)sqlite3_column_text(stmt, 10)) >> userID_C2_payee;
            } catch (...) { sqlite3_finalize(stmt); return -1; }
        } else { sqlite3_finalize(stmt); return -1; }
        sqlite3_finalize(stmt);

        // 복호화 (생략 가능하나 원본 유지)
        Fp12 temp_pow, rPayer, rPayee;
        Fp12::pow(temp_pow, userID_C1_payer, x_GE); Fp12::inv(temp_pow, temp_pow); Fp12::mul(rPayer, userID_C2_payer, temp_pow);
        Fp12::pow(temp_pow, userID_C1_payee, x_GE); Fp12::inv(temp_pow, temp_pow); Fp12::mul(rPayee, userID_C2_payee, temp_pow);

        // 다음 연결 찾기 (인덱스가 적용되어 매우 빠름!)
        G1 temp_check_T, fC1_xh;
        G1::mul(fC1_xh, forward_C1, x_h);
        G1::sub(temp_check_T, forward_C2, fC1_xh);
        G1::add(temp_check_T, temp_check_T, bank_B);

        const char* sql_next = "SELECT Ts_num FROM spk_bundle WHERE T = ?;";
        sqlite3_stmt* stmt_next;
        if (sqlite3_prepare_v2(db, sql_next, -1, &stmt_next, nullptr) != SQLITE_OK) return -1;

        string tStr = temp_check_T.getStr(16);
        sqlite3_bind_text(stmt_next, 1, tStr.c_str(), -1, SQLITE_STATIC);

        start_ts_num = -1;
        if (sqlite3_step(stmt_next) == SQLITE_ROW) {
            start_ts_num = sqlite3_column_int(stmt_next, 0);
        }
        sqlite3_finalize(stmt_next);
        
        if (finalised) break;
    }
    return 0;
}

int BackwardTracing(sqlite3* db, int start_ts_num) {
    Fp12 S; G1 T, backward_C1, backward_C2, bank_B;
    
    while (start_ts_num != -1) {
        const char* sql = "SELECT T, backward_C1, backward_C2, bank_B FROM spk_bundle WHERE Ts_num = ?;";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return -1;
        sqlite3_bind_int(stmt, 1, start_ts_num);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
             T.setStr((const char*)sqlite3_column_text(stmt, 0), 16);
             backward_C1.setStr((const char*)sqlite3_column_text(stmt, 1), 16);
             backward_C2.setStr((const char*)sqlite3_column_text(stmt, 2), 16);
             const char* b_raw = (const char*)sqlite3_column_text(stmt, 3);
             if(b_raw && string(b_raw)!="none") bank_B.setStr(b_raw, 16);
        } else { sqlite3_finalize(stmt); return -1; }
        sqlite3_finalize(stmt);
        
        // 이전 연결 찾기 (인덱스 적용됨)
        G1 temp_pow, neg_pow, recovered_ht_t;
        G1::mul(temp_pow, backward_C1, x_h);
        G1::neg(neg_pow, temp_pow);
        G1::add(recovered_ht_t, backward_C2, neg_pow);

        G1 inv_ht_t, target_bank_B;
        G1::neg(inv_ht_t, recovered_ht_t);
        G1::add(target_bank_B, T, inv_ht_t);
        
        const char* sql_find = "SELECT Ts_num FROM spk_bundle WHERE bank_B = ?;";
        sqlite3_stmt* stmt_next;
        if (sqlite3_prepare_v2(db, sql_find, -1, &stmt_next, nullptr) != SQLITE_OK) return -1;
        string bStr = target_bank_B.getStr(16);
        sqlite3_bind_text(stmt_next, 1, bStr.c_str(), -1, SQLITE_STATIC);

        int next_ts = -1;
        if (sqlite3_step(stmt_next) == SQLITE_ROW) {
            next_ts = sqlite3_column_int(stmt_next, 0);
        }
        sqlite3_finalize(stmt_next);
        
        if (next_ts != -1) start_ts_num = next_ts;
        else break;
    }
    return 0;
}

int getRandomTsNum(sqlite3* db) {
    const char* sql = "SELECT Ts_num FROM spk_bundle ORDER BY RANDOM() LIMIT 1;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return -1;
    int ts_num = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) ts_num = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return ts_num;
}

// [핵심] 실험 자동화 함수
void run_experiment(string db_name, string csv_name, int runs) {
    sqlite3* db;
    if (sqlite3_open(db_name.c_str(), &db) != SQLITE_OK) {
        cerr << "❌ DB Open Failed: " << db_name << endl; return;
    }
    
    // SQLite 캐시 최적화 (속도 향상)
    sqlite3_exec(db, "PRAGMA cache_size = 10000;", nullptr, nullptr, nullptr);
    sqlite3_exec(db, "PRAGMA synchronous = OFF;", nullptr, nullptr, nullptr);

    ofstream csv(csv_name);
    csv << "Index,Ts_num,Forward(ms),Backward(ms),Total(ms)\n";
    
    cout << "🚀 Running Experiment on " << db_name << " (" << runs << " runs)..." << endl;

    for (int i = 1; i <= runs; ++i) {
        int ts_num = getRandomTsNum(db);
        if(ts_num == -1) continue;

        auto start_f = high_resolution_clock::now();
        forwardTracing(db, ts_num);
        auto end_f = high_resolution_clock::now();
        double f_time = duration<double, milli>(end_f - start_f).count();

        auto start_b = high_resolution_clock::now();
        BackwardTracing(db, ts_num);
        auto end_b = high_resolution_clock::now();
        double b_time = duration<double, milli>(end_b - start_b).count();

        csv << i << "," << ts_num << "," << f_time << "," << b_time << "," << (f_time + b_time) << "\n";
        
        if (i % 500 == 0) cout << "   Progress: " << i << "/" << runs << "\r" << flush;
    }
    cout << "\n✅ Done! Saved to " << csv_name << endl;
    
    csv.close();
    sqlite3_close(db);
}

int main() {
    initPairing(mcl::BLS12_381); 

    // (파라미터 설정 코드는 그대로 둠)
    G1 g, g0, g1, gE, h, h0, h1, h2, hE, ht; G2 g_G2, h_G2; Fp12 G, GE, H, H1;
    setupH_Generators(h, h0, h1, h2, hE, ht, h_G2); setupG_Generators(g, g0, g1, gE, g_G2);
    alpha = 1; beta = 2; x_GE = 3; x_h = 4;
    pairing(G, g, g_G2); pairing(GE, g1, g_G2); pairing(H, h, h_G2); pairing(H1, h1, h_G2);
    G2::mul(W, g_G2, alpha); G2::mul(X, h_G2, beta); Fp12::pow(P, GE, x_GE); G1::mul(Q, hE, x_h);

    // 3가지 케이스 순차 실행
    const int NUM_RUNS = 2500;
    
    // [중요] DB 파일명은 실제 생성한 파일명과 일치해야 합니다.
    run_experiment("file_for_tracing_BLS381.db",  "tracing_result_BLS381.csv",  NUM_RUNS);

    return 0;
}