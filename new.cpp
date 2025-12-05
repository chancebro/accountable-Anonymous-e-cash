// tracing.cpp

#include "new.h"
#include <mcl/bn.hpp>
#include <functional>

using namespace mcl::bn;
using namespace std::chrono;

mcl::bn::Fr alpha;
mcl::bn::Fr beta;
mcl::bn::Fr x_GE;
mcl::bn::Fr x_h;
mcl::bn::G2 W;
mcl::bn::G2 X;
mcl::bn::Fp12 P;
mcl::bn::G1 Q;
sqlite3* db = nullptr;  // 전역 변수 정의

// Helper toHexStr overloads
std::string toHexStr(const mcl::bn::G1& g) { return g.getStr(16); }
std::string toHexStr(const mcl::bn::Fp12& gt) { return gt.getStr(16); }
std::string toHexStr(const mcl::bn::Fr& f) { return f.getStr(16); }

void hashToG1(mcl::bn::G1& g, const std::string& label) {
    uint32_t seed = std::hash<std::string>{}(label);
    mapToG1(g, seed);
}

void hashToG2(mcl::bn::G2& h, const std::string& label) {
    uint32_t seed = std::hash<std::string>{}(label);
    mapToG2(h, seed);
}

void hashToFr(mcl::bn::Fr &target,const std::string& msg){
    target.setHashOf(msg);  // MCL 내장 함수
}
void hashToGT(mcl::bn::Fp12& target,const std::string& msg) {

    G1 G1;
    hashToG1(G1,msg);
    G2 G2; 
    hashToG2(G2,msg + "#");  // 도메인 분리
    pairing(target, G1, G2);
    
}
void setupG_Generators(G1& g, G1& g0, G1& g1, G1& ge,G2& gk) {
    hashToG1(g,  "g");
    hashToG1(g0, "g0");
    hashToG1(g1, "g1");
    hashToG1(ge, "ge");
    hashToG2(gk, "gk");

}

void setupH_Generators(G1& h, G1& h0, G1& h1, G1& h2,G1 &he,G1 &ht,G2 &g) {
    hashToG1(h,  "h");
    hashToG1(h0, "h0");
    hashToG1(h1, "h1");
    hashToG1(h2, "h2");
    hashToG1(he, "he");
    hashToG1(ht, "ht");
    hashToG2(g,"g");
}


// Prover: 증명 생성
pk_1_proof pk_1_prove(const Fr &sp, const Fr &u, const G1 &g0, const G1 &g1, const G1 &Cm,const Fp12 &G) {
    pk_1_proof proof;
    Fr r_sp, r_u;
    r_sp.setByCSPRNG();
    r_u.setByCSPRNG();

    G1::mul(proof.Cm_sp, g0, r_sp);
    G1::mul(proof.Cm_u, g1, r_u);
    Fp12::pow(proof.U, G,u);
    Fp12::pow(proof.Cm_U, G,r_u);

    proof.c.setByCSPRNG();
    proof.Z_sp = r_sp + proof.c * sp;
    proof.Z_u  = r_u  + proof.c * u;

    return proof;
}

// verify pk1 for account est
bool pk_1_verify(const pk_1_proof &proof, const G1 &Cm, const G1 &g0, const G1 &g1,const Fp12 &G) {
    G1 lhs_g0, lhs_g1, lhs;
    G1::mul(lhs_g0, g0, proof.Z_sp);
    G1::mul(lhs_g1, g1, proof.Z_u);
    G1::add(lhs, lhs_g0, lhs_g1);

    G1 rhs_Cm, rhs_tmp, rhs;
    G1::mul(rhs_Cm, Cm, proof.c);
    G1::add(rhs_tmp, proof.Cm_sp, proof.Cm_u);
    G1::add(rhs, rhs_tmp, rhs_Cm);

    Fp12 U_c,lU;
    Fp12::pow(U_c,proof.U,proof.c);
    Fp12::mul(lU, U_c, proof.Cm_U);
    Fp12 rU;
    Fp12::pow(rU,G,proof.Z_u);

    return (lhs == rhs)&&(lU==rU);
}
bool account_est(User &user_out, mcl::bn::G1& g, mcl::bn::G1& g0, mcl::bn::G1& g1, mcl::bn::G2& g_G2,const mcl::bn::Fp12& G) {
    //user side 1 start
    // Step 1: User generates commitment Cm
    Fr sp;
    sp.setByCSPRNG();
    

    G1 g0sp, g1u, Cm;
    G1::mul(g0sp, g0, sp);
    G1::mul(g1u, g1, user_out.u);
    G1::add(Cm, g0sp, g1u);

    // Step 2: User proves correctness of Cm
    pk_1_proof proof = pk_1_prove(sp, user_out.u, g0, g1, Cm,G);
    //user side 1 end

    //bank side 1 start
    if (!pk_1_verify(proof, Cm,g0, g1,G)) {
        std::cout << "❌ Verification failed: Pk_1 is not valid" << std::endl;
        return false;
    }

    // Step 3: Bank sign on Cm for gen account
    Fr spp, e;
    spp.setByCSPRNG();
    e.setByCSPRNG();

    G1 g0spp, gg0spp, Cm_gg0spp;
    G1::mul(g0spp, g0, spp);
    G1::add(gg0spp, g, g0spp);
    G1::add(Cm_gg0spp, Cm, gg0spp);

    Fr denom = e + alpha;
    Fr inv_denom;
    Fr::inv(inv_denom, denom);

    G1 A;
    G1::mul(A, Cm_gg0spp, inv_denom);//A is signature of bank  
    //bank side 1 end

    //user side 2 start

    // Step 4: Store into User struct
    user_out.A = A;
    user_out.e = e;
    user_out.s = sp + spp;

    // Step 5: Signature verification
    G2 W, he, Whe;
    G2::mul(W, g_G2, alpha);
    G2::mul(he, g_G2, e);
    G2::add(Whe, he, W);

    G1 g0s, gg0s, gg0sg1u;
    G1::mul(g0s, g0, user_out.s);
    G1::add(gg0s, g, g0s);
    G1::add(gg0sg1u, gg0s, g1u);

    Fp12 e1, e2;
    pairing(e1, user_out.A, Whe);
    pairing(e2, gg0sg1u, g_G2);

    if (e1 == e2) {
        //std::cout << "✅ Account establishment successful!" << std::endl;
        return true;
    } else {
        //std::cout << "❌ Signature pairing verification failed!" << std::endl;
        return false;
    }
    //user side 2 end
}
// Prover: 증명 생성
pk_2_proof pk_2_prove(const mcl::bn::Fr &tp, const mcl::bn::Fr &u,const mcl::bn::Fr &vp,
    const mcl::bn::G1 &h0, const mcl::bn::G1 h1, const mcl::bn::G1 h2, const mcl::bn::G1 &Cmp,const mcl::bn::Fp12 &G) {
    pk_2_proof proof;

    Fr r_tp, r_u,r_vp;
    r_tp.setByCSPRNG();
    r_u.setByCSPRNG();
    r_vp.setByCSPRNG();

    G1::mul(proof.Cm_tp, h0, r_tp);
    G1::mul(proof.Cm_u, h1, r_u);
    G1::mul(proof.Cm_vp,h2,r_vp);
    Fp12::pow(proof.Cm_U,G,r_u);
    Fp12::pow(proof.U,G,u);

    proof.c.setByCSPRNG();
    proof.Z_tp = r_tp + proof.c * tp;
    proof.Z_u  = r_u  + proof.c * u;
    proof.Z_vp = r_vp + proof.c * vp;
    proof.Z_U = r_u+proof.c*u;

    return proof;
}

// Verifier: 증명 검증
bool pk_2_verify(const pk_2_proof &proof, const mcl::bn::G1 &Cmp, const mcl::bn::G1 &h0, const mcl::bn::G1 &h1 , const mcl::bn::G1 &h2 ,const mcl::bn::Fp12 &G) {

    G1 lhs_h0, lhs_h1, lhs_h2,temp, lhs;
    G1::mul(lhs_h0, h0, proof.Z_tp);
    G1::mul(lhs_h1, h1, proof.Z_u);
    G1::mul(lhs_h2, h2, proof.Z_vp);
    G1::add(temp,lhs_h0,lhs_h1);
    G1::add(lhs,temp,lhs_h2);

    G1 rhs_Cmp, rhs_temp1, rhs_temp2,rhs;
    G1::mul(rhs_Cmp, Cmp, proof.c);
    G1::add(rhs_temp1, proof.Cm_tp, proof.Cm_u);
    G1::add(rhs_temp2, rhs_temp1, rhs_Cmp);
    G1::add(rhs,rhs_temp2,proof.Cm_vp);

    Fp12 U_c,lU;
    Fp12::pow(U_c,proof.U,proof.c);
    Fp12::mul(lU, U_c, proof.Cm_U);

    Fp12 rU1,rU2,rU;
    Fp12::pow(rU,G,proof.Z_u);
    
    return (lhs == rhs)&&(lU==rU) ;
}
bool withdraw_coin(User &user_out, mcl::bn::G1& h, mcl::bn::G1& h0, mcl::bn::G1& h1,mcl::bn::G1& h2, mcl::bn::G2& h_G2,const mcl::bn::Fp12& G) {
    
    // Step 1: User generates commitment Cm
    //user pick t' v' randomly
    Fr tp,vp;
    tp.setByCSPRNG();
    vp.setByCSPRNG();
    G1 h0_tp,h1_u,h2_vp,temp,Cmp;
    //make Cm' 
    G1::mul(h0_tp,h0,tp);
    G1::mul(h1_u,h1,user_out.u);
    G1::mul(h2_vp,h2,vp);
    G1::add(temp,h0_tp,h1_u);
    G1::add(Cmp,h2_vp,temp);

    //proof Cmp and U
    pk_2_proof proof = pk_2_prove(tp, user_out.u, vp, h0, h1,h2, Cmp,G);
    if (!pk_2_verify(proof, Cmp, h0, h1,h2,G)) {
        std::cout << "❌ Verification failed: Pk_2 is not valid" << std::endl;
        return false;
    }

    //bank pick for sign on coin
    G1 h0_tpp,h2_vpp;
    Fr tpp,vpp,f;
    tpp.setByCSPRNG();
    vpp.setByCSPRNG();
    f.setByCSPRNG();
    G1::mul(h0_tpp,h0,tpp);//h0^t''
    G1::mul(h2_vpp,h2,vpp);//h2^v''
    G1::add(temp,h,h0_tpp);//h*h0^t''
    G1::add(temp,h2_vpp,temp);//h*h0^t''*h2^v''
    G1::add(temp,Cmp,temp);//h*Cm'*h0^t''*h2^v''
    Fr denom = f + beta;//beta+f
    Fr inv_denom;
    Fr::inv(inv_denom, denom);//(1/beta+1)
    G1::mul(user_out.B,temp,inv_denom);//sign

    //user verify generated signature
    Fr t,v;
    user_out.f=f;
    user_out.t=tp+tpp;
    user_out.v=vp+vpp;
    G2 X, hf, Xhf;//X is bank's pubkey
    G2::mul(X, h_G2, beta);
    G2::mul(hf, h_G2, f);
    G2::add(Xhf, hf, X);
    
    //user verify vaidation of coin
    G1 h0t,h2v, h0th1u,h0th1uh2v,hh0th1uh2v;
    G1::mul(h0t, h0, user_out.t);
    G1::mul(h2v, h2, user_out.v);
    G1::add(h0th1u, h0t, h1_u);
    G1::add(h0th1uh2v, h0th1u, h2v);
    G1::add(hh0th1uh2v,h0th1uh2v, h);
    //verifing 
    Fp12 e1, e2;
    pairing(e1, user_out.B, Xhf);
    pairing(e2, hh0th1uh2v, h_G2);

    if (e1 == e2) {
        std::cout << "✅ Coin withdraw successful!" << std::endl;
        return true;
    } else {
        std::cout << "❌ Coin withdraw  failed!" << std::endl;
        return false;
    }
}
pk_3_proof pk_3_prove(User &user_out,const mcl::bn::G1 g, const mcl::bn::G1 &g0, const mcl::bn::G1 g1,const mcl::bn::G2 g_G2, const mcl::bn::Fp12 &G,std::string INFO) {
    Fr r1,r2;
    Fr delta1,delta2;
    G1 g0r1,g1r2,g1r1;
    G1 g0d1,g1d2;//d1 mean delta1,d2 mean delta2
    
    G2 W;
    G2::mul(W,g_G2,alpha);

    r1.setByCSPRNG();
    r2.setByCSPRNG();
    delta1=r1*user_out.e;
    delta2=r2*user_out.e;

    pk_3_proof proof;
    //user n하고 info저장
    user_out.N.setByCSPRNG();
    proof.N=user_out.N;
    //proof를 위한 n하고 ifo저장
    user_out.INFO=INFO;
    proof.INFO=INFO;

    std::string input = user_out.INFO + user_out.N.getStr(10);
    Fp12 G_t_info;
    hashToGT(G_t_info,input);

    //M생성 후 proof와 user에 저장장
    Fp12::pow(proof.M,G_t_info,user_out.u);
    Fp12::pow(user_out.M,G_t_info,user_out.u);

    G1::mul(g0r1,g0,r1);
    G1::mul(g1r2,g1,r2);
    G1::mul(g1r1,g1,r1);

    G1::add(proof.A1,g0r1,g1r2);
    G1::mul(proof.A1e,proof.A1,user_out.e);
    G1::add(proof.A2,user_out.A,g1r1);
    
    //pick random value for pk3
    Fr r_r1,r_r2,r_d1,r_d2,r_s,r_u,r_e,c;

    r_r1.setByCSPRNG();
    r_r2.setByCSPRNG();
    r_d1.setByCSPRNG();
    r_d2.setByCSPRNG();
    r_s.setByCSPRNG();
    r_u.setByCSPRNG();
    r_e.setByCSPRNG();
    c.setByCSPRNG();
    proof.c=c;
   
    //gen Commit
    //G1 g0r1,g1r2;
    Fp12 ee,er1,ed1,es,eu;

    G1 g0r_r1,g1r_r2;
    G1::mul(g0r_r1,g0,r_r1);
    G1::mul(g1r_r2,g1,r_r2);
    G1::add(proof.Cm_A1,g0r_r1,g1r_r2);

    G1::mul(proof.Cm_A1e,proof.A1,r_e);

    pairing(ee,proof.A2,g_G2);
    Fp12::pow(proof.Cm_ee,ee,r_e);
    pairing(er1,g1,W);
    Fp12::pow(proof.Cm_er1,er1,r_r1);
    pairing(ed1,g1,g_G2);
    Fp12::pow(proof.Cm_ed1,ed1,r_d1);
    pairing(es,g0,g_G2);
    Fp12::pow(proof.Cm_es,es,r_s);
    pairing(eu,g1,g_G2);
    Fp12::pow(proof.Cm_eu,eu,r_u);


    Fp12::pow(proof.Cm_M,G_t_info,r_u);

    //gen Z
    proof.Z_r1=r_r1+c*r1;
    proof.Z_r2=r_r2+c*r2;
    proof.Z_d1=r_d1+c*delta1;
    proof.Z_d2=r_d2+c*delta2;
    proof.Z_s=r_s+c*user_out.s;
    proof.Z_u=r_u+c*user_out.u;
    proof.Z_e=r_e+c*user_out.e;

    return proof;
}
bool pk_3_verify(const pk_3_proof &proof, const mcl::bn::G1 g, const mcl::bn::G1 &g0, const mcl::bn::G1 g1,const mcl::bn::G2 g_G2, const mcl::bn::Fp12 &G) {

    G1 lA1,rA1,A1c,g0Z_r1,g1Z_r2;
    G1::mul(A1c,proof.A1,proof.c);
    G1::add(lA1,proof.Cm_A1,A1c);
    G1::mul(g0Z_r1,g0,proof.Z_r1);
    G1::mul(g1Z_r2,g1,proof.Z_r2);
    G1::add(rA1,g0Z_r1,g1Z_r2);
    //std::cout << "[A1 검증] " << (lA1 == rA1 ? "✅ 성공" : "❌ 실패") << std::endl;

    G1 lA1e,rA1e,A1ec,g0Z_d1,g1Z_d2;
    G1::mul(A1ec,proof.A1e,proof.c);
    G1::add(lA1e,proof.Cm_A1e,A1ec);
    G1::mul(rA1e,proof.A1,proof.Z_e);

    //G1::mul(g1Z_d2,g1,proof.Z_d2); 
    //G1::add(rA1e,g0Z_d1,g1Z_d2);

    //std::cout << "[A1e 검증] " << (lA1e == rA1e ? "✅ 성공" : "❌ 실패") << std::endl;

    Fp12 e_A2w, e_gg_G2, result;

    pairing(e_A2w, proof.A2, W);       // e(A2, w)
    pairing(e_gg_G2, g, g_G2);     // e(g0, h0)

    Fp12 inv_e_gg_G2;
    Fp12::inv(inv_e_gg_G2, e_gg_G2);   // 역원 계산
    Fp12::mul(result, e_A2w, inv_e_gg_G2); // 최종 결과 계산

    Fp12 templ1,templ2,templ3,templ4,el,resultc,inv_Cm_ee;

    Fp12::pow(resultc,result,proof.c);

    Fp12::inv(inv_Cm_ee,proof.Cm_ee);

    Fp12::mul(templ1,inv_Cm_ee,proof.Cm_er1);

    Fp12::mul(templ2,proof.Cm_ed1,templ1);
    Fp12::mul(templ3,proof.Cm_es,templ2);
    Fp12::mul(templ4,proof.Cm_eu,templ3);
    Fp12::mul(el,templ4,resultc);

    Fp12 tempr1,tempr2,tempr3,tempr4,tempr5,inv_tempr1,er;

    Fp12 ee,er1,ed1,es,eu;

    pairing(ee,proof.A2,g_G2);
    pairing(er1,g1,W);
    pairing(ed1,g1,g_G2);
    pairing(es,g0,g_G2);
    pairing(eu,g1,g_G2);


    Fp12::pow(tempr1,ee,proof.Z_e);
    Fp12::inv(inv_tempr1, tempr1);   // 역원 계산
    Fp12::pow(tempr2,er1,proof.Z_r1);
    Fp12::pow(tempr3,ed1,proof.Z_d1);
    Fp12::pow(tempr4,es,proof.Z_s);
    Fp12::pow(tempr5,eu,proof.Z_u);
    Fp12 t1,t2,t3;
    Fp12::mul(t1,inv_tempr1,tempr2);
    Fp12::mul(t2,t1,tempr3);
    Fp12::mul(t3,t2,tempr4);
    Fp12::mul(er,t3,tempr5);

    //std::cout << "[페어링 검증] " << (er == el ? "✅ 성공" : "❌ 실패") << std::endl;

    //gen G(Info||N)


    std::string input = proof.INFO + proof.N.getStr(10);
    Fp12 G_t_info;
    hashToGT(G_t_info,input);

    Fp12 M_c,lM;
    Fp12::pow(M_c,proof.M,proof.c);
    Fp12::mul(lM, M_c, proof.Cm_M);

    Fp12 rM;
    Fp12::pow(rM,G_t_info ,proof.Z_u);

    //std::cout << "[M 검증] " << (lU==rU ? "✅ 성공" : "❌ 실패") << std::endl;


    return (lA1 == rA1)&&(lA1e == rA1e)&&(er == el)&&(lM==rM) ;
}

SPK1_proof SPK1_prove(User &user_out,const mcl::bn::G1 h, const mcl::bn::G1 &h0, const mcl::bn::G1 h1, const mcl::bn::G1 h2,const mcl::bn::G1 hE,const mcl::bn::G1 ht,const mcl::bn::G2 h_G2,const mcl::bn::Fp12 &H ,const mcl::bn::Fp12 &H1,
    const mcl::bn::Fp12 &G,const mcl::bn::Fp12 &GE,std::string INFO,pk_3_proof pk_3) {
        
    Fr r1,r2;
    Fr gamma1,gamma2;
    G1 h0r1,h1r2,h1r1;
    G1 h0g1,h1g2;//d1 mean delta1,d2 mean delta2
    
    //pick random r1,r1 and calculate delta1,delta2 for spk

    r1.setByCSPRNG();
    r2.setByCSPRNG();

    gamma1=r1*user_out.f;
    gamma2=r2*user_out.f;

    SPK1_proof proof;
    

    //calculate S,D

    //gen S
    Fp12::pow(proof.S,H,user_out.v);//ex1
    //gen D
    Fp12 temp_D1,temp_D2;
    std::string input = INFO + pk_3.N.getStr(10)+pk_3.M.getStr(10);
    proof.N=pk_3.N;
    proof.M=pk_3.M;
    Fr R;
    hashToFr(R,input);
    proof.R=R;
    Fp12::pow(temp_D1,H1,R);//ex2
    Fp12::pow(temp_D2,temp_D1,user_out.v);//ex3
    Fp12::mul(proof.D,user_out.U,temp_D2);//mp1
    

    G1::mul(h0r1,h0,r1);//mp2
    G1::mul(h1r2,h1,r2);//mp3
    G1::mul(h1r1,h1,r1);//mp4

    G1::add(proof.B1,h0r1,h1r2);
    G1::mul(proof.B1f,proof.B1,user_out.f);//mp5
    G1::add(proof.B2,user_out.B,h1r1);
    
    //pick random value for spk
    Fr r_r1,r_r2,r_g1,r_g2,r_t,r_u,r_v,r_f,c;

    r_r1.setByCSPRNG();
    r_r2.setByCSPRNG();
    r_g1.setByCSPRNG();
    r_g2.setByCSPRNG();
    r_t.setByCSPRNG();
    r_u.setByCSPRNG();
    r_f.setByCSPRNG();
    r_v.setByCSPRNG();
    c.setByCSPRNG();
    proof.c=c;
    //gen Cm_S and Cm_D
    Fp12 temp_cmD1,temp_cmD2;
    //gen Cm_S
    Fp12::pow(proof.Cm_S,H,r_v);//ex4
    //gen Cm_D
    Fp12::pow(temp_cmD1,G,r_u);//ex5
    Fp12::pow(temp_cmD2,H1,R);//ex6
    Fp12::pow(temp_cmD2,temp_cmD2,r_v);//ex7
    Fp12::mul(proof.Cm_D,temp_cmD1,temp_cmD2);//mp6
   
    //gen Commit for prove pairing
    //G1 g0r1,g1r2;
    Fp12 Bef,Ber1,Beg1,Bet,Beu,Bev;

    G1 h0r_r1,h1r_r2;
    G1::mul(h0r_r1,h0,r_r1);//mp7
    G1::mul(h1r_r2,h1,r_r2);//mp8
    G1::add(proof.Cm_B1,h0r_r1,h1r_r2);

    G1::mul(proof.Cm_B1f,proof.B1,r_f);//mp9


    pairing(Bef,proof.B2,h_G2);//bp1
    Fp12::pow(proof.Cm_Bef,Bef,r_f);//ex8
    pairing(Ber1,h1,X);//bp2
    Fp12::pow(proof.Cm_Ber1,Ber1,r_r1);//ex9
    pairing(Beg1,h1,h_G2);//bp3
    Fp12::pow(proof.Cm_Beg1,Beg1,r_g1);//ex10
    pairing(Bet,h0,h_G2);//bp4
    Fp12::pow(proof.Cm_Bet,Bet,r_t);//ex11
    pairing(Beu,h1,h_G2);//bp5
    Fp12::pow(proof.Cm_Beu,Beu,r_u);//ex12
    pairing(Bev,h2,h_G2);//bp6
    Fp12::pow(proof.Cm_Bev,Bev,r_v);//ex13

    //gen userID_C1,C2
    Fp12 temp_uID;
    //uID C1
    Fp12::pow(proof.userID_C1,GE,r1);//ex14
    //uID C2
    Fp12::pow(temp_uID,P,r1);//ex15
    Fp12::mul(proof.userID_C2,user_out.U,temp_uID);//mp10
    //std::cout << "userID_payer_C2: " << proof.userID_C2<< "\n";
    //Commit for uid C1
    Fp12::pow(proof.Cm_GE,GE,r_r1);//ex16
    //commit for uid C2
    Fp12::pow(proof.Cm_G,G,r_u);//ex17
    Fp12::pow(proof.Cm_P,P,r_r1);//ex18

    //gen tracing tag T
    G1 ht_t;//backward tag
    G1::mul(ht_t,ht,user_out.t);//mp11
    G1::add(proof.T,user_out.B,ht_t);
    G1::mul(proof.Cm_T,ht,r_t);//mp12

    //gen encrypted backward tag
    G1 Qr1;
    G1::mul(proof.backward_C1,hE,r1);//mp13

    G1::mul(Qr1,Q,r1);//mp14
    G1::add(proof.backward_C2,Qr1,ht_t);

    G1 ht_r_t,Q_r_r1;
    G1::mul(proof.Cm_backward_r1,h1,r_r1);//mp15
    G1::mul(proof.Cm_backward_C1,hE,r_r1);//mp16

    G1::mul(ht_r_t,ht,r_t);//mp17
    G1::mul(Q_r_r1,Q,r_r1);//mp18
    G1::add(proof.Cm_backward_C2,Q_r_r1,ht_r_t);

    //gen Z
    proof.Z_r1=r_r1+c*r1;
    proof.Z_r2=r_r2+c*r2;
    proof.Z_g1=r_g1+c*gamma1;
    proof.Z_g2=r_g2+c*gamma2;
    proof.Z_t=r_t+c*user_out.t;
    proof.Z_u=r_u+c*user_out.u;
    proof.Z_f=r_f+c*user_out.f;
    proof.Z_v=r_v+c*user_out.v;

    return proof;
}

bool SPK1_verify(const SPK1_proof &proof, const mcl::bn::G1 h, const mcl::bn::G1 &h0, const mcl::bn::G1 h1, const mcl::bn::G1 h2,const mcl::bn::G1 hE,const mcl::bn::G1 ht,const mcl::bn::G2 h_G2,const mcl::bn::Fp12 &H ,const mcl::bn::Fp12 &H1,
    const mcl::bn::Fp12 &G,const mcl::bn::Fp12 &GE) {

    G1 lB1,rB1,B1c,h0Z_r1,h1Z_r2;
    G1::mul(B1c,proof.B1,proof.c);//mp1
    G1::add(lB1,proof.Cm_B1,B1c);
    G1::mul(h0Z_r1,h0,proof.Z_r1);//mp2
    G1::mul(h1Z_r2,h1,proof.Z_r2);//mp3
    G1::add(rB1,h0Z_r1,h1Z_r2);
    //std::cout << "[B1 검증] " << (lB1 == rB1 ? "✅ 성공" : "❌ 실패") << std::endl;

    G1 lB1f,rB1f,B1fc,h0Z_d1,h1Z_d2;
    G1::mul(B1fc,proof.B1f,proof.c);//mp4
    G1::add(lB1f,proof.Cm_B1f,B1fc);
    G1::mul(rB1f,proof.B1,proof.Z_f);//mp5

    //std::cout << "[B1e 검증] " << (lB1f == rB1f ? "✅ 성공" : "❌ 실패") << std::endl;

    Fp12 e_B2X, e_hh_G2, resultB;

    pairing(e_B2X, proof.B2, X);//bp1       // e(A2, w)
    pairing(e_hh_G2, h, h_G2);//bp2     // e(g0, h0)

    Fp12 inv_e_hh_G2;
    Fp12::inv(inv_e_hh_G2, e_hh_G2);   // 역원 계산
    Fp12::mul(resultB, e_B2X, inv_e_hh_G2);//mp6 // 최종 결과 계산
    
    Fp12 Btempl1,Btempl2,Btempl3,Btempl4,Btempl5,Bel,resultBc,Binv_Cm_ee;

    Fp12::pow(resultBc,resultB,proof.c);//ex1

    Fp12::inv(Binv_Cm_ee,proof.Cm_Bef);

    Fp12::mul(Btempl1,Binv_Cm_ee,proof.Cm_Ber1);//mp6

    Fp12::mul(Btempl2,proof.Cm_Beg1,Btempl1);//mp7
    Fp12::mul(Btempl3,proof.Cm_Bet,Btempl2);//mp8
    Fp12::mul(Btempl4,proof.Cm_Beu,Btempl3);//mp9
    Fp12::mul(Btempl5,proof.Cm_Bev,Btempl4);//mp10
    Fp12::mul(Bel,Btempl5,resultBc);//mp11

    Fp12 Btempr1,Btempr2,Btempr3,Btempr4,Btempr5,Btempr6,Binv_tempr1,Ber;

    Fp12 Bef,Ber1,Beg1,Bet,Beu,Bev;

    pairing(Bef,proof.B2,h_G2);//bp3
    pairing(Ber1,h1,X);//bp4
    pairing(Beg1,h1,h_G2);//bp5
    pairing(Bet,h0,h_G2);//bp6
    pairing(Beu,h1,h_G2);//bp7
    pairing(Bev,h2,h_G2);//bp8
    

    Fp12::pow(Btempr1,Bef,proof.Z_f);//ex2
    Fp12::inv(Binv_tempr1, Btempr1);   // 역원 계산
    
    Fp12::pow(Btempr2,Ber1,proof.Z_r1);//ex4
    Fp12::pow(Btempr3,Beg1,proof.Z_g1);//ex5
    Fp12::pow(Btempr4,Bet,proof.Z_t);//ex6
    Fp12::pow(Btempr5,Beu,proof.Z_u);//ex7
    Fp12::pow(Btempr6,Bev,proof.Z_v);//ex8

    Fp12 Bt1,Bt2,Bt3,Bt4;

    Fp12::mul(Bt1,Binv_tempr1,Btempr2);//mp12
    Fp12::mul(Bt2,Bt1,Btempr3);//mp13
    Fp12::mul(Bt3,Bt2,Btempr4);//mp14
    Fp12::mul(Bt4,Bt3,Btempr5);//mp15
    Fp12::mul(Ber,Bt4,Btempr6);//mp16

    //std::cout << "[코인 페어링 검증] " << (Ber == Bel ? "✅ 성공" : "❌ 실패") << std::endl;

    //S 검증

    Fp12 S_c,lS,rS;
    Fp12::pow(S_c,proof.S,proof.c);//ex9
    Fp12::mul(lS, S_c, proof.Cm_S);//mp17

    Fp12::pow(rS,H ,proof.Z_v);//ex10

    //std::cout << "[S 검증] " << (lS==rS ? "✅ 성공" : "❌ 실패") << std::endl;

    //D 검증

    Fp12 D_c,lD,rD,temp_rD1,temp_rD2;
    Fp12::pow(D_c,proof.D,proof.c);//ex11
    Fp12::mul(lD, D_c, proof.Cm_D);//mp18

    Fp12::pow(temp_rD1,G ,proof.Z_u);//ex12
    Fp12::pow(temp_rD2,H1 ,proof.R);//ex13
    Fp12::pow(temp_rD2,temp_rD2 ,proof.Z_v);//ex14
    Fp12::mul(rD,temp_rD1,temp_rD2);//mp19

    //std::cout << "[D 검증] " << (lD==rD ? "✅ 성공" : "❌ 실패") << std::endl;

    Fp12 lID_C1,rID_C1,temp_ID_C1;

    Fp12::pow(temp_ID_C1,proof.userID_C1,proof.c);//ex15
    Fp12::mul(lID_C1,proof.Cm_GE,temp_ID_C1);//mp19
    Fp12::pow(rID_C1,GE,proof.Z_r1);//ex16

    //std::cout << "[user ID C1 검증] " << (lID_C1==rID_C1? "✅ 성공" : "❌ 실패") << std::endl;
    
    Fp12 lID_C2,rID_C2,temp_ID_C2_1,temp_ID_C2_2;
    Fp12::pow(temp_ID_C2_1,proof.userID_C2,proof.c);//ex17
    Fp12::mul(temp_ID_C2_2,proof.Cm_G,proof.Cm_P);//mp20
    Fp12::mul(lID_C2,temp_ID_C2_1,temp_ID_C2_2);//mp21

    Fp12::pow(temp_ID_C2_1,G,proof.Z_u);//ex18
    Fp12::pow(temp_ID_C2_2,P,proof.Z_r1);//ex19
    Fp12::mul(rID_C2,temp_ID_C2_1,temp_ID_C2_2);//mp22

    //std::cout << "[user ID C2 검증] " << (lID_C2==rID_C2? "✅ 성공" : "❌ 실패") << std::endl;

    G1 lT,temp_T,inv_CmT,inv_T;

    G1::neg(inv_CmT,proof.Cm_T);
    G1::add(temp_T,proof.Cm_backward_r1,inv_CmT);

    G1::neg(inv_T,proof.T);
    G1::add(lT,proof.B2,inv_T);
    G1::mul(lT,lT,proof.c);//mp23

    G1::add(lT,lT,temp_T);

    G1 rT,h1_Zr1,inv_ht_Zt,ht_Zt;
    G1::mul(ht_Zt,ht,proof.Z_t);//mp24
    G1::neg(inv_ht_Zt,ht_Zt);

    G1::mul(h1_Zr1,h1,proof.Z_r1);//mp25
    G1::add(rT,inv_ht_Zt,h1_Zr1);


    //std::cout << "[T 검증] " << (rT == lT ? "✅ 성공" : "❌ 실패") << std::endl;
    
    G1 lBackC1;
    G1::mul(lBackC1,proof.backward_C1,proof.c);//mp25
    G1::add(lBackC1,proof.Cm_backward_C1,lBackC1);
    G1 rBackC1;
    G1::mul(rBackC1,hE,proof.Z_r1);//mp26

    //std::cout << "[Backward tag C1 검증] " << (lBackC1 == rBackC1 ? "✅ 성공" : "❌ 실패") << std::endl;

    G1 lBackC2,temp_lBackC2;

    
    G1::mul(temp_lBackC2,proof.backward_C2,proof.c);//mp27
    G1::add(lBackC2,proof.Cm_backward_C2,temp_lBackC2);

    G1 rBackC2,temp_rBackC21,temp_rBackC22;
    G1::mul(temp_rBackC21,ht,proof.Z_t);//mp28
    G1::mul(temp_rBackC22,Q,proof.Z_r1);//mp29
    G1::add(rBackC2,temp_rBackC21,temp_rBackC22);

    //std::cout << "[Backward tag C2 검증] " << (lBackC2 == rBackC2 ? "✅ 성공" : "❌ 실패") << std::endl;

    
    return (lB1 == rB1)&&(lB1f == rB1f)&&(Ber == Bel)&&(lS==rS)&&(lD==rD)&&(lID_C1==rID_C1)&&(lID_C2==rID_C2)&&(rT == lT )&&(lBackC1 == rBackC1)&&(lBackC2 == rBackC2); 
}
bool Payment(User& payer, User& payee,
    const mcl::bn::G1& g, const mcl::bn::G1& g0, const mcl::bn::G1& g1,const mcl::bn::G1& gE,
    const mcl::bn::G2& g_G2, const mcl::bn::Fp12& G,const mcl::bn::Fp12& GE,
    const mcl::bn::G1& h, const mcl::bn::G1& h0, const mcl::bn::G1& h1,
    const mcl::bn::G1& h2,const mcl::bn::G1& hE,const mcl::bn::G1& ht, const mcl::bn::G2& h_G2,
    const mcl::bn::Fp12& H, const mcl::bn::Fp12& H1){
    // Step 1: pk_3 proof 생성
    //payee side1 start
        std::string INFO="please send me coin";
    
    pk_3_proof pk3 = pk_3_prove(payee, g, g0, g1, g_G2, G, INFO);//7mp+8ex+5bp

    //payee side1 end

    //payer side1 start
    // Step 2: pk_3 검증
    if (!pk_3_verify(pk3, g, g0, g1, g_G2, G)) {//16mp+7ex+7bp
        std::cout << "❌ Verification failed: pk_3 is not valid" << std::endl;
        return false;
    }
    // Step 3: SPK proof 생성
    SPK1_proof spk1 = SPK1_prove(payer, h, h0, h1, h2, hE,ht,h_G2, H, H1,G,GE, INFO, pk3);//18mp+18ex+6bp
    //payer side1 end

    //payee side 2 start
    // Step 4: SPK 검증
    if (!SPK1_verify(spk1,  h, h0, h1, h2,hE,ht ,h_G2, H, H1,G,GE)) {//29mp+19ex+8bp
        std::cout << "❌ Verification failed: SPK is not valid" << std::endl;
        return false;
    }
    

    
    // Step 5: 증명 통과 → 저장 및 성공 메시지
    payee.spk1 = spk1;
    //payee side 2 end
    //std::cout << "✅ Payment completed successfully." << std::endl;
    return true;

}



// Prover: 증명 생성
pk_5_proof pk_5_prove(User &user_out,const mcl::bn::Fr &tp,const mcl::bn::Fr &vp,
    const mcl::bn::G1 &h0, const mcl::bn::G1 h1, const mcl::bn::G1 h2, const mcl::bn::G1 &Cmp,const mcl::bn::Fp12 &G) {

    pk_5_proof proof;

    proof.N=user_out.N;
    proof.M=user_out.M;

    Fr r_tp, r_u,r_vp;
    r_tp.setByCSPRNG();
    r_u.setByCSPRNG();
    r_vp.setByCSPRNG();

    std::string input = proof.INFO + proof.N.getStr(10);
    Fp12 G_t_info;
    hashToGT(G_t_info,input);

    G1::mul(proof.Cm_tp, h0, r_tp);//mp1
    G1::mul(proof.Cm_u, h1, r_u);//mp2
    G1::mul(proof.Cm_vp,h2,r_vp);//mp3

    Fp12::pow(proof.M,G_t_info,user_out.u);//ex1
    
    Fp12::pow(proof.Cm_M,G_t_info,r_u);//ex2

    proof.c.setByCSPRNG();
    proof.Z_tp = r_tp + proof.c * tp;
    proof.Z_u  = r_u  + proof.c * user_out.u;
    proof.Z_vp = r_vp + proof.c * vp;
    

    return proof;
}

// Verifier: 증명 검증
bool pk_5_verify(const pk_5_proof &proof, const mcl::bn::G1 &Cmp ,const mcl::bn::G1 &h0, const mcl::bn::G1 &h1 , const mcl::bn::G1 &h2 ,const mcl::bn::Fp12 &G) {

    G1 lhs_h0, lhs_h1, lhs_h2,temp, lhs;
    G1::mul(lhs_h0, h0, proof.Z_tp);//mp1
    G1::mul(lhs_h1, h1, proof.Z_u);//mp2
    G1::mul(lhs_h2, h2, proof.Z_vp);//mp3
    G1::add(temp,lhs_h0,lhs_h1);
    G1::add(lhs,temp,lhs_h2);

    G1 rhs_Cmp, rhs_temp1, rhs_temp2,rhs;
    G1::mul(rhs_Cmp, Cmp, proof.c);//mp4
    G1::add(rhs_temp1, proof.Cm_tp, proof.Cm_u);
    G1::add(rhs_temp2, rhs_temp1, rhs_Cmp);
    G1::add(rhs,rhs_temp2,proof.Cm_vp);
    //std::cout << "[Cm' 검증] " << (lhs==rhs ? "✅ 성공" : "❌ 실패") << std::endl;

    std::string input = proof.INFO + proof.N.getStr(10);
    Fp12 G_t_info;
    hashToGT(G_t_info,input);

    Fp12 M_c,lM;
    Fp12::pow(M_c,proof.M,proof.c);//ex1
    Fp12::mul(lM, M_c, proof.Cm_M);//mp5

    Fp12 rM;
    Fp12::pow(rM,G_t_info ,proof.Z_u);//ex2

    //std::cout << "[M 검증] " << (lM==rM ? "✅ 성공" : "❌ 실패") << std::endl;
    
    return (lhs == rhs)&&(lM==rM ) ;
}
SPK2_proof SPK2_prove(User &user_out,const mcl::bn::G1 g, const mcl::bn::G1 &g0, const mcl::bn::G1 g1,const mcl::bn::G2 g_G2, const mcl::bn::Fp12 &G,const mcl::bn::Fp12 &GE) {
   
    Fr r1,r2;
    Fr delta1,delta2;
    G1 g0r1,g1r2,g1r1;
    G1 g0d1,g1d2;//d1 mean delta1,d2 mean delta2
    
    

    r1.setByCSPRNG();
    r2.setByCSPRNG();
    delta1=r1*user_out.e;
    delta2=r2*user_out.e;

    SPK2_proof proof;
    //user n하고 info저장
    proof.N=user_out.N;
    //proof를 위한 n하고 ifo저장
    proof.INFO=user_out.INFO;

    std::string input = user_out.INFO + user_out.N.getStr(10);
    Fp12 G_t_info;
    hashToGT(G_t_info,input);

    //M생성 후 proof와 user에 저장장
    Fp12::pow(proof.M,G_t_info,user_out.u);//ex1
    Fp12::pow(user_out.M,G_t_info,user_out.u);//ex2

    G1::mul(g0r1,g0,r1);//mp1
    G1::mul(g1r2,g1,r2);//mp2
    G1::mul(g1r1,g1,r1);//mp3

    G1::add(proof.A1,g0r1,g1r2);
    G1::mul(proof.A1e,proof.A1,user_out.e);//mp4
    G1::add(proof.A2,user_out.A,g1r1);
    
    //pick random value for pk3
    Fr r_r1,r_r2,r_d1,r_d2,r_s,r_u,r_e,c;

    r_r1.setByCSPRNG();
    r_r2.setByCSPRNG();
    r_d1.setByCSPRNG();
    r_d2.setByCSPRNG();
    r_s.setByCSPRNG();
    r_u.setByCSPRNG();
    r_e.setByCSPRNG();
    c.setByCSPRNG();
    proof.c=c;
   
    //gen Commit
    //G1 g0r1,g1r2;
    Fp12 ee,er1,ed1,es,eu;

    G1 g0r_r1,g1r_r2;
    G1::mul(g0r_r1,g0,r_r1);//mp5
    G1::mul(g1r_r2,g1,r_r2);//mp6
    G1::add(proof.Cm_A1,g0r_r1,g1r_r2);

    G1::mul(proof.Cm_A1e,proof.A1,r_e);//mp7

    pairing(ee,proof.A2,g_G2);//bp1
    Fp12::pow(proof.Cm_ee,ee,r_e);//ex3
    pairing(er1,g1,W);//bp2
    Fp12::pow(proof.Cm_er1,er1,r_r1);//ex4
    pairing(ed1,g1,g_G2);//bp3
    Fp12::pow(proof.Cm_ed1,ed1,r_d1);//ex5
    pairing(es,g0,g_G2);//bp4
    Fp12::pow(proof.Cm_es,es,r_s);//ex6
    pairing(eu,g1,g_G2);//bp5
    Fp12::pow(proof.Cm_eu,eu,r_u);//ex7


    Fp12::pow(proof.Cm_M,G_t_info,r_u);//ex8
   
     //gen userID_C1,C2
     Fp12 temp_uID;
     //uID C1
     Fp12::pow(proof.userID_C1,GE,r1);//ex9
     //uID C2
     Fp12::pow(temp_uID,P,r1);//ex10
     Fp12::mul(proof.userID_C2,user_out.U,temp_uID);//mp7

    // std::cout << "[debug] user_out.U = " << user_out.U.getStr(16) << std::endl;
     //std::cout << "[debug] P = " << P << std::endl;
     //std::cout << "[debug] r1 = " << r1 << std::endl;
     //std::cout << "[debug] userID_C2: " << proof.userID_C2 << "\n";

     //Commit for uid C1
     Fp12::pow(proof.Cm_GE,GE,r_r1);//ex11
     //commit for uid C2
     Fp12::pow(proof.Cm_G,G,r_u);//ex12
     Fp12::pow(proof.Cm_P,P,r_r1); //ex13

    //gen Z
    proof.Z_r1=r_r1+c*r1;
    proof.Z_r2=r_r2+c*r2;
    proof.Z_d1=r_d1+c*delta1;
    proof.Z_d2=r_d2+c*delta2;
    proof.Z_s=r_s+c*user_out.s;
    proof.Z_u=r_u+c*user_out.u;
    proof.Z_e=r_e+c*user_out.e;

    
    return proof;
}
bool SPK2_verify(const SPK2_proof &proof, const mcl::bn::G1 g, const mcl::bn::G1 &g0, const mcl::bn::G1 g1,const mcl::bn::G2 g_G2, const mcl::bn::Fp12 &G,const mcl::bn::Fp12 &GE) {

    G1 lA1,rA1,A1c,g0Z_r1,g1Z_r2;
    G1::mul(A1c,proof.A1,proof.c);//mp1
    G1::add(lA1,proof.Cm_A1,A1c);
    G1::mul(g0Z_r1,g0,proof.Z_r1);//mp2
    G1::mul(g1Z_r2,g1,proof.Z_r2);//mp3
    G1::add(rA1,g0Z_r1,g1Z_r2);
    //std::cout << "[A1 검증] " << (lA1 == rA1 ? "✅ 성공" : "❌ 실패") << std::endl;

    G1 lA1e,rA1e,A1ec,g0Z_d1,g1Z_d2;
    G1::mul(A1ec,proof.A1e,proof.c);//mp4
    G1::add(lA1e,proof.Cm_A1e,A1ec);
    G1::mul(rA1e,proof.A1,proof.Z_e);//mp5

    //G1::mul(g1Z_d2,g1,proof.Z_d2); 
    //G1::add(rA1e,g0Z_d1,g1Z_d2);

    //std::cout << "[A1e 검증] " << (lA1e == rA1e ? "✅ 성공" : "❌ 실패") << std::endl;

    Fp12 e_A2w, e_gg_G2, result;

    pairing(e_A2w, proof.A2, W);//bp1       // e(A2, w)
    pairing(e_gg_G2, g, g_G2);//bp2     // e(g0, h0)

    Fp12 inv_e_gg_G2;
    Fp12::inv(inv_e_gg_G2, e_gg_G2);   // 역원 계산
    Fp12::mul(result, e_A2w, inv_e_gg_G2);//mp6  // 최종 결과 계산

    Fp12 templ1,templ2,templ3,templ4,el,resultc,inv_Cm_ee;

    Fp12::pow(resultc,result,proof.c);//ex1

    Fp12::inv(inv_Cm_ee,proof.Cm_ee);

    Fp12::mul(templ1,inv_Cm_ee,proof.Cm_er1);//mp7

    Fp12::mul(templ2,proof.Cm_ed1,templ1);//mp8
    Fp12::mul(templ3,proof.Cm_es,templ2);//mp9
    Fp12::mul(templ4,proof.Cm_eu,templ3);//mp10
    Fp12::mul(el,templ4,resultc);//mp11

    Fp12 tempr1,tempr2,tempr3,tempr4,tempr5,inv_tempr1,er;

    Fp12 ee,er1,ed1,es,eu;

    pairing(ee,proof.A2,g_G2);//bp3
    pairing(er1,g1,W);//bp4
    pairing(ed1,g1,g_G2);//bp5
    pairing(es,g0,g_G2);//bp6
    pairing(eu,g1,g_G2);//bp7


    Fp12::pow(tempr1,ee,proof.Z_e);//ex2
    Fp12::inv(inv_tempr1, tempr1);   // 역원 계산
    Fp12::pow(tempr2,er1,proof.Z_r1);//ex3
    Fp12::pow(tempr3,ed1,proof.Z_d1);//ex4
    Fp12::pow(tempr4,es,proof.Z_s);//ex5
    Fp12::pow(tempr5,eu,proof.Z_u);//ex6
    Fp12 t1,t2,t3;
    Fp12::mul(t1,inv_tempr1,tempr2);//mp12
    Fp12::mul(t2,t1,tempr3);//mp13
    Fp12::mul(t3,t2,tempr4);//mp14
    Fp12::mul(er,t3,tempr5);//mp15

    //std::cout << "[페어링 검증] " << (er == el ? "✅ 성공" : "❌ 실패") << std::endl;

    //gen G(Info||N)


    std::string input = proof.INFO + proof.N.getStr(10);
    Fp12 G_t_info;
    hashToGT(G_t_info,input);

    Fp12 M_c,lM;
    Fp12::pow(M_c,proof.M,proof.c);//ex7
    Fp12::mul(lM, M_c, proof.Cm_M);//mp16

    Fp12 rM;
    Fp12::pow(rM,G_t_info ,proof.Z_u);//ex8

    //std::cout << "[M 검증] " << (lM==rM ? "✅ 성공" : "❌ 실패") << std::endl;

    Fp12 lID_C1,rID_C1,temp_ID_C1;

    Fp12::pow(temp_ID_C1,proof.userID_C1,proof.c);//ex9
    Fp12::mul(lID_C1,proof.Cm_GE,temp_ID_C1);//mp17
    Fp12::pow(rID_C1,GE,proof.Z_r1);//10

    //std::cout << "[user ID C1 검증] " << (lID_C1==rID_C1? "✅ 성공" : "❌ 실패") << std::endl;
    
    Fp12 lID_C2,rID_C2,temp_ID_C2_1,temp_ID_C2_2;
    Fp12::pow(temp_ID_C2_1,proof.userID_C2,proof.c);//ex11
    Fp12::mul(temp_ID_C2_2,proof.Cm_G,proof.Cm_P);//mp18
    Fp12::mul(lID_C2,temp_ID_C2_1,temp_ID_C2_2);//mp19

    Fp12::pow(temp_ID_C2_1,G,proof.Z_u);//ex12
    Fp12::pow(temp_ID_C2_2,P,proof.Z_r1);//ex13
    Fp12::mul(rID_C2,temp_ID_C2_1,temp_ID_C2_2);//mp20

    //std::cout << "[user ID C2 검증] " << (lID_C2==rID_C2? "✅ 성공" : "❌ 실패") << std::endl;


    return (lA1 == rA1)&&(lA1e == rA1e)&&(er == el)&&(lM==rM)&&(lID_C1==rID_C1)&&(lID_C2==rID_C2) ;
}


SPK3_proof SPK3_prove(User &user_out,const mcl::bn::G1 h, const mcl::bn::G1 &h0, const mcl::bn::G1 h1, const mcl::bn::G1 h2,const mcl::bn::G1 hE,const mcl::bn::G1 ht,const mcl::bn::G2 h_G2) {

    SPK3_proof proof;
    
    
    Fr r_t,r_u,r_v,r1,r_r1;
    r1.setByCSPRNG();
    r_r1.setByCSPRNG();
    r_t.setByCSPRNG();
    r_u.setByCSPRNG();
    r_v.setByCSPRNG();

    G1::mul(proof.Cm_h0,h0,r_t);//mp1
    G1::mul(proof.Cm_h1,h1,r_u);//mp2
    G1::mul(proof.Cm_h2,h2,r_v);//mp3

  
    proof.c.setByCSPRNG();
   
   

    //gen encrypted backward tag
    G1 Qr1,ht_t;
    G1::mul(ht_t,ht,user_out.t);//mp4
    G1::mul(proof.forward_C1,hE,r1);//mp5

    G1::mul(Qr1,Q,r1);//mp6
    G1::add(proof.forward_C2,Qr1,ht_t);

    G1 ht_r_t,Q_r_r1;
    G1::mul(proof.Cm_forward_r1,h1,r_r1);//mp7
    G1::mul(proof.Cm_forward_C1,hE,r_r1);//mp8

    G1::mul(ht_r_t,ht,r_t);//mp9
    G1::mul(Q_r_r1,Q,r_r1);//mp10
    G1::add(proof.Cm_forward_C2,Q_r_r1,ht_r_t);

    //gen Z
    
    proof.Z_t=r_t+proof.c*user_out.t;
    proof.Z_u=r_u+proof.c*user_out.u;
    proof.Z_v=r_v+proof.c*user_out.v;
    proof.Z_r1 = r_r1 + proof.c * r1;

    return proof;
}

bool SPK3_verify(const SPK3_proof &proof, const mcl::bn::G1& h, const mcl::bn::G1 &h0, const mcl::bn::G1& h1,const mcl::bn::G1& h2,const mcl::bn::G1 hE,const mcl::bn::G1 ht,const mcl::bn::G2 &h_G2,mcl::bn::G1 &bank_B,mcl::bn::Fr &bank_f) {

    G2  hf, Xhf;
   
    G2::mul(hf, h_G2, bank_f);//mp1
    G2::add(Xhf, hf, X);

    Fp12 e1, e2,le;
    pairing(e1, bank_B, Xhf);//bp1
    Fp12::pow(e1,e1,proof.c);//ex1

    G1 temp;
    G1::add(temp,proof.Cm_h0,proof.Cm_h1);
    G1::add(temp,temp,proof.Cm_h2);

    pairing(e2,temp,h_G2);//bp2

    Fp12::mul(le,e1,e2);//mp2

    G1 h_c,h0_Zt,h1_Zu,h2_Zv;

    Fp12 re;
    G1::mul(h_c,h,proof.c);//mp3
    G1::mul(h0_Zt,h0,proof.Z_t);//mp4
    G1::mul(h1_Zu,h1,proof.Z_u);//mp5
    G1::mul(h2_Zv,h2,proof.Z_v);//mp6

    G1::add(temp,h_c,h0_Zt);
    G1::add(temp,temp,h1_Zu);
    G1::add(temp,temp,h2_Zv);

    pairing(re,temp,h_G2);//bp3//bp3

    //std::cout << "[계정 검증 검증] " << (le == re ? "✅ 성공" : "❌ 실패") << std::endl;

    G1 lBackC1;
    G1::mul(lBackC1,proof.forward_C1,proof.c);//mp7
    G1::add(lBackC1,proof.Cm_forward_C1,lBackC1);
    G1 rBackC1;
    G1::mul(rBackC1,hE,proof.Z_r1);//mp8

    //std::cout << "[Backward tag C1 검증] " << (lBackC1 == rBackC1 ? "✅ 성공" : "❌ 실패") << std::endl;

    G1 lBackC2,temp_lBackC2;

    
    G1::mul(temp_lBackC2,proof.forward_C2,proof.c);//mp9
    G1::add(lBackC2,proof.Cm_forward_C2,temp_lBackC2);

    G1 rBackC2,temp_rBackC21,temp_rBackC22;
    G1::mul(temp_rBackC21,ht,proof.Z_t);//mp10
    G1::mul(temp_rBackC22,Q,proof.Z_r1);//mp11
    G1::add(rBackC2,temp_rBackC21,temp_rBackC22);

    //std::cout << "[Backward tag C2 검증] " << (lBackC2 == rBackC2 ? "✅ 성공" : "❌ 실패") << std::endl;
    

    return (lBackC1 == rBackC1)&&(lBackC2 == rBackC2);
    }
bool randomise(User &user,
    const mcl::bn::G1 &g, const mcl::bn::G1 &g0, const mcl::bn::G1 &g1, const mcl::bn::G2 &g_G2, const mcl::bn::Fp12 &G,const mcl::bn::Fp12 &GE,
    const mcl::bn::G1 &h, const mcl::bn::G1 &h0, const mcl::bn::G1 &h1, const mcl::bn::G1 &h2,const mcl::bn::G1 &hE,const mcl::bn::G1 &ht, const mcl::bn::G2 &h_G2, const mcl::bn::Fp12 &H, const mcl::bn::Fp12 &H1)
{
    //payee side1 start
    G1 bank_B;
    SPK2_proof spk2 = SPK2_prove(user, g, g0, g1, g_G2, G, GE);//7mp+13ex+5bp
    //payee side1 end

    //bank side1 start
    if (!SPK2_verify(spk2, g, g0, g1, g_G2, G, GE)) return false;//20mp+13ex+7bp
    user.spk2 = spk2;

    if (!SPK1_verify(user.spk1, h, h0, h1, h2, hE, ht, h_G2, H, H1, G, GE)) return false;//29mp+19ex+8bp

    if (checkDoubleSpending(db,user.spk1.S)) {//DB에 가서 spk의 s가 존재하는지 안 존재하는지 판단단
        std::cout << "❌ Coin rejected: Double spending detected." << std::endl;
        return false;
    }
   //bank side1 end

   //payee side2 start
    // Step 1: User generates commitment Cm
    Fr tp, vp;
    tp.setByCSPRNG();
    vp.setByCSPRNG();

    G1 h0_tp, h1_u, h2_vp, temp, Cmp;
    G1::mul(h0_tp, h0, tp);//mp1
    G1::mul(h1_u, h1, user.u);//mp2
    G1::mul(h2_vp, h2, vp);//mp3
    G1::add(temp, h0_tp, h1_u);
    G1::add(Cmp, h2_vp, temp);
    //3mp

    // Step 2: Prove knowledge of Cm'
    pk_5_proof pk5 = pk_5_prove(user,tp, vp, h0, h1, h2, Cmp, G);//3mp+2ex
    //payee side2 end

    //bank side2 start
    if (!pk_5_verify(pk5, Cmp, h0, h1, h2, G)) {//5mp+2ex
        std::cout << "❌ Verification failed: Pk_2 is not valid" << std::endl;
        return false;
    }

    // Step 3: Bank signs the new coin
    Fr tpp, vpp, f,bank_f;
    tpp.setByCSPRNG();
    vpp.setByCSPRNG();
    f.setByCSPRNG();
    bank_f=f;

    G1 h0_tpp, h2_vpp;
    G1::mul(h0_tpp, h0, tpp);//mp1
    G1::mul(h2_vpp, h2, vpp);//mp2
    G1::add(temp, h, h0_tpp);
    G1::add(temp, h2_vpp, temp);
    G1::add(temp, Cmp, temp);

    Fr denom = f + beta;
    Fr inv_denom;
    Fr::inv(inv_denom, denom);
    G1::mul(user.B, temp, inv_denom);//mp3
    //mp3

    bank_B=user.B;//user가 발급받은 코인 B를 뱅크도 알고있음음
    //bank side2 end

    
    //payee side 3 start
    // Step 4: Update user secret
    user.f = f;
    user.t = tp + tpp;
    user.v = vp + vpp;

    // Step 5: Verify randomized coin
    G1 h0t, h2v, h0th1u, h0th1uh2v, hh0th1uh2v;
    G1::mul(h0t, h0, user.t);//mp1
    G1::mul(h2v, h2, user.v);//mp2
    G1::add(h0th1u, h0t, h1_u);
    G1::add(h0th1uh2v, h0th1u, h2v);
    G1::add(hh0th1uh2v, h0th1uh2v, h);

    G2  hf, Xhf;
   
    G2::mul(hf, h_G2, f);//mp3
    G2::add(Xhf, hf, X);

    Fp12 e1, e2;
    pairing(e1, user.B, Xhf);//bp1
    pairing(e2, hh0th1uh2v, h_G2);//bp2
    //3mp+2bp

    if (e1 == e2) {
        //std::cout << "✅ Coin randomise successful!" << std::endl;
    } else {
        //std::cout << "❌ Coin randomise failed!" << std::endl;
        return false;
    }

    SPK3_proof spk3 = SPK3_prove(user, h, h0, h1, h2,hE,ht,h_G2);//10mp
    //payee side 3 end

    //bank side 3 start
    if (!SPK3_verify(spk3, h, h0, h1,h2,hE,ht, h_G2,bank_B,bank_f)) {//11mp+1ex+sbp
        std::cout << "❌ Verification failed: SPK3 is not valid" << std::endl;
        return false;
    }
    user.spk3=spk3;

    //Step 0.6: Double Spending 아니라면 DB에 등록
    insertSPKProof(db, user.spk1,  user.spk2,user.spk3 ,bank_B);
    //bank side 3 end
    
    
    //forward tracing되나? 한번 해본거...
    /*G1 temp_check_T, fC1_xh;
    G1::mul(fC1_xh, spk3.forward_C1, x_h);       // forward_C1 * x_h
    G1::sub(temp_check_T, spk3.forward_C2, fC1_xh); // forward_C2 - forward_C1 * x_h
    G1::add(temp_check_T, temp_check_T, bank_B);   // + bank_B

    G1 forward_T;
    G1::mul(forward_T, ht, user.t);
    G1::add(forward_T, forward_T, bank_B);

    std::cout << "[forward 트레이싱 검증] " << (temp_check_T == forward_T ? "✅ 성공" : "❌ 실패") << std::endl;*/
   
    return true;
}
bool finalise(User &user,
    const mcl::bn::G1 &g, const mcl::bn::G1 &g0, const mcl::bn::G1 &g1, const mcl::bn::G2 &g_G2, const mcl::bn::Fp12 &G,const mcl::bn::Fp12 &GE,
    const mcl::bn::G1 &h, const mcl::bn::G1 &h0, const mcl::bn::G1 &h1, const mcl::bn::G1 &h2,const mcl::bn::G1 &hE,const mcl::bn::G1 &ht, const mcl::bn::G2 &h_G2, const mcl::bn::Fp12 &H, const mcl::bn::Fp12 &H1)
{
    G1 bank_B;
    //payee side 1 start
    SPK2_proof spk2 = SPK2_prove(user, g, g0, g1, g_G2, G, GE);//7mp+13ex+5bp
    //payee side 1 end

    //bank side 1 start
    if (!SPK2_verify(spk2, g, g0, g1, g_G2, G, GE)) return false;//20mp+13ex+7bp
    user.spk2 = spk2;

    if (!SPK1_verify(user.spk1, h, h0, h1, h2, hE, ht, h_G2, H, H1, G, GE)) return false;//29mp+19ex+8bp

    if (checkDoubleSpending(db,user.spk1.S)) {//DB에 가서 spk의 s가 존재하는지 안 존재하는지 판단단
        std::cout << "❌ Coin rejected: Double spending detected." << std::endl;
        return false;
    }
    
    //bank side 1 end

    

    //Step 0.6: Double Spending 아니라면 DB에 등록
    insertSPKProofForFinalise(db, user.spk1,  user.spk2);
    
   
    return true;
}
bool initDatabase(sqlite3*& db) {
    int rc = sqlite3_open("Tracing_sample.db", &db);
    if (rc != SQLITE_OK) {
        std::cerr << "❌ Failed to open database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    // 1. [성능 최적화] 시뮬레이션 속도를 위해 안전장치 해제 (필수)
    sqlite3_exec(db, "PRAGMA synchronous = OFF;", nullptr, nullptr, nullptr);
    sqlite3_exec(db, "PRAGMA journal_mode = MEMORY;", nullptr, nullptr, nullptr);
    sqlite3_exec(db, "PRAGMA temp_store = MEMORY;", nullptr, nullptr, nullptr);

    // 2. 테이블 생성 (모든 필드 포함)
    const char* createTableSQL = R"(
        CREATE TABLE IF NOT EXISTS spk_bundle (
            Ts_num INTEGER PRIMARY KEY AUTOINCREMENT,
            S TEXT,
            D TEXT,
            INFO TEXT,
            R TEXT,
            N TEXT,
            M TEXT,
            T TEXT,
            backward_C1 TEXT,
            backward_C2 TEXT,
            bank_B TEXT,
            forward_C1 TEXT,
            forward_C2 TEXT,
            userID_payer_C1 TEXT,
            userID_payer_C2 TEXT,
            userID_payee_C1 TEXT,
            userID_payee_C2 TEXT
        );
    )";

    const char* createUsersTableSQL = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            U TEXT
        );
    )";

    // 3. [인덱스 생성] 검색에 사용되는 핵심 컬럼들에 목차 달기 (매우 중요!)
    // - S: 이중 지불 탐지용
    // - T, bank_B: 백워드/포워드 트레이싱 검색용
    const char* createIndexSQL = R"(
        CREATE INDEX IF NOT EXISTS idx_S ON spk_bundle (S);
        CREATE INDEX IF NOT EXISTS idx_T ON spk_bundle (T);
        CREATE INDEX IF NOT EXISTS idx_bank_B ON spk_bundle (bank_B);
        CREATE INDEX IF NOT EXISTS idx_R ON spk_bundle (R);
    )";

    char* errMsg = nullptr;

    // 테이블 생성 실행
    rc = sqlite3_exec(db, createTableSQL, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "❌ Table creation failed: " << errMsg << std::endl;
        sqlite3_free(errMsg); sqlite3_close(db); return false;
    }

    rc = sqlite3_exec(db, createUsersTableSQL, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "❌ Users Table creation failed: " << errMsg << std::endl;
        sqlite3_free(errMsg); sqlite3_close(db); return false;
    }

    // 인덱스 생성 실행
    rc = sqlite3_exec(db, createIndexSQL, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "❌ Index creation failed: " << errMsg << std::endl;
        sqlite3_free(errMsg); sqlite3_close(db); return false;
    }

    std::cout << "✅ Database initialized with Optimization & Indexes.\n";
    return true;
}

// 사용자 U 삽입 함수는 변경 사항 없음, 그대로 유지
bool insertUserU(sqlite3* db, int user_id, const mcl::bn::Fp12& U) {
    std::string uStr = U.getStr(16);

    std::stringstream ss;
    ss << "INSERT INTO users (id, U) VALUES (" << user_id << ", '" << uStr << "');";

    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, ss.str().c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "❌ U 삽입 실패 (user_id=" << user_id << "): " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }

    std::cout << "✅ User" << user_id << " U 삽입 성공\n";
    return true;
}

bool insertSPKProof(sqlite3* db,
    const SPK1_proof& spk1,
    const SPK2_proof& spk2,
    const SPK3_proof& spk3,
    const mcl::bn::G1& bank_B) {

    // 1. 값 변환 (Hex String)
    // SPK1에서 가져오는 값들
    std::string sStr = spk1.S.getStr(16);
    std::string dStr = spk1.D.getStr(16);
    std::string rStr = spk1.R.getStr(16);
    std::string nStr = spk1.N.getStr(16);
    std::string mStr = spk1.M.getStr(16);
    std::string tStr = spk1.T.getStr(16);
    std::string bC1Str = spk1.backward_C1.getStr(16);
    std::string bC2Str = spk1.backward_C2.getStr(16);
    std::string uid1C1Str = spk1.userID_C1.getStr(16);
    std::string uid1C2Str = spk1.userID_C2.getStr(16);

    // SPK2에서 가져오는 값들 (INFO, Payee ID)
    std::string infoStr = spk2.INFO; // std::string 그대로 사용
    std::string uid2C1Str = spk2.userID_C1.getStr(16);
    std::string uid2C2Str = spk2.userID_C2.getStr(16);

    // SPK3에서 가져오는 값들 (Forward Tag)
    std::string fC1Str = spk3.forward_C1.getStr(16);
    std::string fC2Str = spk3.forward_C2.getStr(16);

    // Bank Signature
    std::string bankStr = bank_B.getStr(16);


    // 2. 쿼리 생성
    std::stringstream ss;
    ss << "INSERT INTO spk_bundle ("
       << "S, D, INFO, R, N, M, T, backward_C1, backward_C2, bank_B, forward_C1, forward_C2, "
       << "userID_payer_C1, userID_payer_C2, userID_payee_C1, userID_payee_C2) VALUES ('"
       << sStr << "', '" << dStr << "', '" << infoStr << "', '" << rStr << "', '" 
       << nStr << "', '" << mStr << "', '" << tStr << "', '" << bC1Str << "', '" << bC2Str << "', '"
       << bankStr << "', '" << fC1Str << "', '" << fC2Str << "', '"
       << uid1C1Str << "', '" << uid1C2Str << "', '" << uid2C1Str << "', '" << uid2C2Str << "');";

    // 3. 실행
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, ss.str().c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "❌ Insert failed: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }

    // std::cout << "✅ SPK references saved to DB.\n";
    return true;
}

bool insertSPKProofForFinalise(sqlite3* db,
    const SPK1_proof& spk1,
    const SPK2_proof& spk2) {

    // 1. 값 변환
    // SPK1 값들
    std::string sStr = spk1.S.getStr(16);
    std::string dStr = spk1.D.getStr(16);
    std::string rStr = spk1.R.getStr(16);
    std::string nStr = spk1.N.getStr(16);
    std::string mStr = spk1.M.getStr(16);
    std::string tStr = spk1.T.getStr(16);
    std::string bC1Str = spk1.backward_C1.getStr(16);
    std::string bC2Str = spk1.backward_C2.getStr(16);
    std::string uid1C1Str = spk1.userID_C1.getStr(16);
    std::string uid1C2Str = spk1.userID_C2.getStr(16);

    // SPK2 값들
    std::string infoStr = spk2.INFO;
    std::string uid2C1Str = spk2.userID_C1.getStr(16);
    std::string uid2C2Str = spk2.userID_C2.getStr(16);

    // Finalise 단계에서는 SPK3와 bank_B 정보가 없으므로 "none" 처리
    std::string none = "none";

    // 디버깅용 출력 (필요시 주석 해제)
    /*
    std::cout << "============ DB INSERT (Finalise) DEBUG ============" << std::endl;
    std::cout << "[DEBUG] S: " << sStr << std::endl;
    std::cout << "====================================================" << std::endl;
    */

    // 2. 쿼리 생성
    std::stringstream ss;
    ss << "INSERT INTO spk_bundle ("
       << "S, D, INFO, R, N, M, T, backward_C1, backward_C2, bank_B, forward_C1, forward_C2, "
       << "userID_payer_C1, userID_payer_C2, userID_payee_C1, userID_payee_C2) VALUES ('"
       << sStr << "', '" << dStr << "', '" << infoStr << "', '" << rStr << "', '" 
       << nStr << "', '" << mStr << "', '" << tStr << "', '" << bC1Str << "', '" << bC2Str << "', '"
       << none << "', '" << none << "', '" << none << "', '"
       << uid1C1Str << "', '" << uid1C2Str << "', '" << uid2C1Str << "', '" << uid2C2Str << "');";

    // 3. 실행
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, ss.str().c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "❌ Insert failed (Finalise): " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }

    // std::cout << "✅ Finalised SPK1/SPK2 data saved to DB.\n";
    return true;
}

bool checkDoubleSpending(sqlite3* db, const mcl::bn::Fp12& S) {
    std::string sStr = S.getStr(16);
    std::string query = "SELECT COUNT(*) FROM spk_bundle WHERE S = ?;";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "❌ Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, sStr.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        int count = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        if (count > 0) {
            std::cout << "🚨 Double Spending Detected! Matching S exists in DB." << std::endl;
            return true;
        } else {
            std::cout << "✅ No double spending detected (S is unique)." << std::endl;
            return false;
        }
    } else {
        std::cerr << "❌ Failed to execute statement." << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }
}

bool account_est_time(User &user_out, mcl::bn::G1& g, mcl::bn::G1& g0, mcl::bn::G1& g1, mcl::bn::G2& g_G2, const mcl::bn::Fp12& G,
    long long& user1_time, long long& bank_time, long long& user2_time) {
auto t1 = high_resolution_clock::now();

// --- User side 1 ---
Fr sp;
sp.setByCSPRNG();

G1 g0sp, g1u, Cm;
G1::mul(g0sp, g0, sp);
G1::mul(g1u, g1, user_out.u);
G1::add(Cm, g0sp, g1u);

pk_1_proof proof = pk_1_prove(sp, user_out.u, g0, g1, Cm, G);

auto t2 = high_resolution_clock::now();

// --- Bank side ---
if (!pk_1_verify(proof, Cm, g0, g1, G)) {
std::cout << "❌ Verification failed: Pk_1 is not valid" << std::endl;
return false;
}

Fr spp, e;
spp.setByCSPRNG();
e.setByCSPRNG();

G1 g0spp, gg0spp, Cm_gg0spp;
G1::mul(g0spp, g0, spp);
G1::add(gg0spp, g, g0spp);
G1::add(Cm_gg0spp, Cm, gg0spp);

Fr denom = e + alpha;
Fr inv_denom;
Fr::inv(inv_denom, denom);

G1 A;
G1::mul(A, Cm_gg0spp, inv_denom);

auto t3 = high_resolution_clock::now();

// --- User side 2 ---
user_out.A = A;
user_out.e = e;
user_out.s = sp + spp;

G2 W, he, Whe;
G2::mul(W, g_G2, alpha);
G2::mul(he, g_G2, e);
G2::add(Whe, he, W);

G1 g0s, gg0s, gg0sg1u;
G1::mul(g0s, g0, user_out.s);
G1::add(gg0s, g, g0s);
G1::add(gg0sg1u, gg0s, g1u);

Fp12 e1, e2;
pairing(e1, user_out.A, Whe);
pairing(e2, gg0sg1u, g_G2);

auto t4 = high_resolution_clock::now();

user1_time = duration_cast<nanoseconds>(t2 - t1).count();
bank_time  = duration_cast<nanoseconds>(t3 - t2).count();
user2_time = duration_cast<nanoseconds>(t4 - t3).count();

return e1 == e2;
}
bool withdraw_coin_time(User &user_out, mcl::bn::G1& h, mcl::bn::G1& h0, mcl::bn::G1& h1, mcl::bn::G1& h2,
    mcl::bn::G2& h_G2, const mcl::bn::Fp12& G,
    long long& user1_time, long long& bank_time, long long& user2_time) {

auto t1 = high_resolution_clock::now();

// --- User side 1 ---
Fr tp, vp;
tp.setByCSPRNG();
vp.setByCSPRNG();

G1 h0_tp, h1_u, h2_vp, temp, Cmp;
G1::mul(h0_tp, h0, tp);
G1::mul(h1_u, h1, user_out.u);
G1::mul(h2_vp, h2, vp);
G1::add(temp, h0_tp, h1_u);
G1::add(Cmp, h2_vp, temp);

pk_2_proof proof = pk_2_prove(tp, user_out.u, vp, h0, h1, h2, Cmp, G);

auto t2 = high_resolution_clock::now();
// --- Bank side ---
if (!pk_2_verify(proof, Cmp, h0, h1, h2, G)) {
std::cout << "❌ Verification failed: Pk_2 is not valid" << std::endl;
return false;
}




G1 h0_tpp, h2_vpp;
Fr tpp, vpp, f;
tpp.setByCSPRNG();
vpp.setByCSPRNG();
f.setByCSPRNG();

G1::mul(h0_tpp, h0, tpp);
G1::mul(h2_vpp, h2, vpp);
G1::add(temp, h, h0_tpp);
G1::add(temp, h2_vpp, temp);
G1::add(temp, Cmp, temp);

Fr denom = f + beta;
Fr inv_denom;
Fr::inv(inv_denom, denom);
G1::mul(user_out.B, temp, inv_denom);

auto t3 = high_resolution_clock::now();

// --- User side 2 ---
user_out.f = f;
user_out.t = tp + tpp;
user_out.v = vp + vpp;

G2 X, hf, Xhf;
G2::mul(X, h_G2, beta);
G2::mul(hf, h_G2, f);
G2::add(Xhf, hf, X);

G1 h0t, h2v, h0th1u, h0th1uh2v, hh0th1uh2v;
G1::mul(h0t, h0, user_out.t);
G1::mul(h2v, h2, user_out.v);
G1::add(h0th1u, h0t, h1_u);
G1::add(h0th1uh2v, h0th1u, h2v);
G1::add(hh0th1uh2v, h0th1uh2v, h);

Fp12 e1, e2;
pairing(e1, user_out.B, Xhf);
pairing(e2, hh0th1uh2v, h_G2);

auto t4 = high_resolution_clock::now();

// 시간 기록
user1_time = duration_cast<nanoseconds>(t2 - t1).count();
bank_time  = duration_cast<nanoseconds>(t3 - t2).count();
user2_time = duration_cast<nanoseconds>(t4 - t3).count();

return (e1 == e2);
}
bool Payment_time(User& payer, User& payee,
    const mcl::bn::G1& g, const mcl::bn::G1& g0, const mcl::bn::G1& g1, const mcl::bn::G1& gE,
    const mcl::bn::G2& g_G2, const mcl::bn::Fp12& G, const mcl::bn::Fp12& GE,
    const mcl::bn::G1& h, const mcl::bn::G1& h0, const mcl::bn::G1& h1,
    const mcl::bn::G1& h2, const mcl::bn::G1& hE, const mcl::bn::G1& ht, const mcl::bn::G2& h_G2,
    const mcl::bn::Fp12& H, const mcl::bn::Fp12& H1,
    long long& payee1_time, long long& payer_time, long long& payee2_time)
{
    std::string INFO = "please send me coin";

    auto t1 = high_resolution_clock::now();

    // --- Payee side 1 ---
    pk_3_proof pk3 = pk_3_prove(payee, g, g0, g1, g_G2, G, INFO);

    auto t2 = high_resolution_clock::now();

    // --- Payer side 1 ---
    if (!pk_3_verify(pk3, g, g0, g1, g_G2, G)) {
        std::cout << "❌ Verification failed: pk_3 is not valid" << std::endl;
        return false;
    }

    SPK1_proof spk1 = SPK1_prove(payer, h, h0, h1, h2, hE, ht, h_G2, H, H1, G, GE, INFO, pk3);

    auto t3 = high_resolution_clock::now();

    // --- Payee side 2 ---
    if (!SPK1_verify(spk1, h, h0, h1, h2, hE, ht, h_G2, H, H1, G, GE)) {
        std::cout << "❌ Verification failed: SPK is not valid" << std::endl;
        return false;
    }

    payee.spk1 = spk1;

    auto t4 = high_resolution_clock::now();

    payee1_time = duration_cast<nanoseconds>(t2 - t1).count();
    payer_time  = duration_cast<nanoseconds>(t3 - t2).count();
    payee2_time = duration_cast<nanoseconds>(t4 - t3).count();

    return true;
}
bool randomise_time(User &user,
    const mcl::bn::G1 &g, const mcl::bn::G1 &g0, const mcl::bn::G1 &g1, const mcl::bn::G2 &g_G2, const mcl::bn::Fp12 &G, const mcl::bn::Fp12 &GE,
    const mcl::bn::G1 &h, const mcl::bn::G1 &h0, const mcl::bn::G1 &h1, const mcl::bn::G1 &h2, const mcl::bn::G1 &hE, const mcl::bn::G1 &ht, const mcl::bn::G2 &h_G2,
    const mcl::bn::Fp12 &H, const mcl::bn::Fp12 &H1,
    long long &t1, long long &t2, long long &t3, long long &t4, long long &t5, long long &t6)
{
    auto start1 = high_resolution_clock::now();

    // --- Payee side 1 ---
    G1 bank_B;
    SPK2_proof spk2 = SPK2_prove(user, g, g0, g1, g_G2, G, GE);

    auto start2 = high_resolution_clock::now();

    // --- Bank side 1 ---
    if (!SPK2_verify(spk2, g, g0, g1, g_G2, G, GE)) {
        std::cerr << "❌ SPK2 verification failed\n";
        return false;
    }

    if (!SPK1_verify(user.spk1, h, h0, h1, h2, hE, ht, h_G2, H, H1, G, GE)) {
        std::cerr << "❌ SPK1 verification failed\n";
        return false;
    }

    auto start3 = high_resolution_clock::now();

    user.spk2 = spk2;
    // --- Payee side 2 ---
    Fr tp, vp;
    tp.setByCSPRNG();
    vp.setByCSPRNG();

    G1 h0_tp, h1_u, h2_vp, temp, Cmp;
    G1::mul(h0_tp, h0, tp);
    G1::mul(h1_u, h1, user.u);
    G1::mul(h2_vp, h2, vp);
    G1::add(temp, h0_tp, h1_u);
    G1::add(Cmp, h2_vp, temp);

    pk_5_proof pk5 = pk_5_prove(user, tp, vp, h0, h1, h2, Cmp, G);

    auto start4 = high_resolution_clock::now();

    // --- Bank side 2 ---
    if (!pk_5_verify(pk5, Cmp, h0, h1, h2, G)) {
        std::cerr << "❌ pk_5 verification failed\n";
        return false;
    }

    Fr tpp, vpp, f, bank_f;
    tpp.setByCSPRNG();
    vpp.setByCSPRNG();
    f.setByCSPRNG();
    bank_f = f;

    G1 h0_tpp, h2_vpp;
    G1::mul(h0_tpp, h0, tpp);
    G1::mul(h2_vpp, h2, vpp);
    G1::add(temp, h, h0_tpp);
    G1::add(temp, h2_vpp, temp);
    G1::add(temp, Cmp, temp);

    Fr denom = f + beta;
    Fr inv_denom;
    Fr::inv(inv_denom, denom);
    G1::mul(user.B, temp, inv_denom);
    bank_B = user.B;

    auto start5 = high_resolution_clock::now();

    // --- Payee side 3 ---
    user.f = f;
    user.t = tp + tpp;
    user.v = vp + vpp;

    G1 h0t, h2v, h0th1u, h0th1uh2v, hh0th1uh2v;
    G1::mul(h0t, h0, user.t);
    G1::mul(h2v, h2, user.v);
    G1::add(h0th1u, h0t, h1_u);
    G1::add(h0th1uh2v, h0th1u, h2v);
    G1::add(hh0th1uh2v, h0th1uh2v, h);

    G2 hf, Xhf;
    G2::mul(hf, h_G2, f);
    G2::add(Xhf, hf, X);

    Fp12 e1, e2;
    pairing(e1, user.B, Xhf);
    pairing(e2, hh0th1uh2v, h_G2);
    if (e1 != e2) {
        std::cerr << "❌ pairing check failed\n";
        return false;
    }

    SPK3_proof spk3 = SPK3_prove(user, h, h0, h1, h2, hE, ht, h_G2);

    auto start6 = high_resolution_clock::now();

    // --- Bank side 3 ---
    if (!SPK3_verify(spk3, h, h0, h1, h2, hE, ht, h_G2, bank_B, bank_f)) {
        std::cerr << "❌ SPK3 verification failed\n";
        return false;
    }

    
    insertSPKProof(db, user.spk1, user.spk2, spk3, bank_B);

    auto end = high_resolution_clock::now();

    // 기록
    t1 = duration_cast<nanoseconds>(start2 - start1).count();
    t2 = duration_cast<nanoseconds>(start3 - start2).count();
    t3 = duration_cast<nanoseconds>(start4 - start3).count();
    t4 = duration_cast<nanoseconds>(start5 - start4).count();
    t5 = duration_cast<nanoseconds>(start6 - start5).count();
    t6 = duration_cast<nanoseconds>(end    - start6).count();

    return true;
}

bool finalise_time(User &user,
    const mcl::bn::G1 &g, const mcl::bn::G1 &g0, const mcl::bn::G1 &g1, const mcl::bn::G2 &g_G2, const mcl::bn::Fp12 &G, const mcl::bn::Fp12 &GE,
    const mcl::bn::G1 &h, const mcl::bn::G1 &h0, const mcl::bn::G1 &h1, const mcl::bn::G1 &h2, const mcl::bn::G1 &hE, const mcl::bn::G1 &ht,
    const mcl::bn::G2 &h_G2, const mcl::bn::Fp12 &H, const mcl::bn::Fp12 &H1,
    long long &payee_time, long long &bank_time)
{
    auto t1 = high_resolution_clock::now();

    // --- Payee side 1 ---
    SPK2_proof spk2 = SPK2_prove(user, g, g0, g1, g_G2, G, GE);

    auto t2 = high_resolution_clock::now();

    // --- Bank side 1 ---
    if (!SPK2_verify(spk2, g, g0, g1, g_G2, G, GE)) return false;
    user.spk2 = spk2;

    if (!SPK1_verify(user.spk1, h, h0, h1, h2, hE, ht, h_G2, H, H1, G, GE)) return false;

    insertSPKProofForFinalise(db, user.spk1, user.spk2);

    auto t3 = high_resolution_clock::now();

    // 기록
    payee_time = duration_cast<nanoseconds>(t2 - t1).count();
    bank_time  = duration_cast<nanoseconds>(t3 - t2).count();

    return true;
}