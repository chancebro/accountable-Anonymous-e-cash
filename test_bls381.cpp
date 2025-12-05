#include <iostream>
#include <stdexcept>
#include <mcl/bn.hpp>

using namespace mcl::bn;

int main()
{
    try {
        // BLS12-381로 초기화
        initPairing(mcl::BLS12_381);
        std::cout << "initPairing(BLS12_381) OK" << std::endl;

        G1 P;
        G2 Q;
        Fp12 e;

        // 간단하게: 미리 정의된 베이스 포인트 사용
        mcl::bn::hashAndMapToG1(P, "test_g1", 7); 
        mcl::bn::hashAndMapToG2(Q, "test_g2", 7);

        pairing(e, P, Q);
        std::cout << "pairing(P, Q) OK" << std::endl;
        // 원하면 값도 출력 가능
        std::cout << "e = " << e << std::endl;
    } catch (const std::exception& ex) {
        std::cerr << "exception: " << ex.what() << std::endl;
        return 1;
    }
    return 0;
}