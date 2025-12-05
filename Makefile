CXX = g++
CXXFLAGS = -I./mcl/include -DMCL_USE_BLS12_381=1 -O2 -g

# SQLite를 쓰는 실행파일용 링크 옵션
LDFLAGS = ./mcl/lib/libmcl.a -lsqlite3 -lpthread

# SQLite 안 쓰는 간단 테스트용 (test_bls381)
LDFLAGS_NO_SQL = ./mcl/lib/libmcl.a -lpthread

# ------------------------------------------------
# 기본 : 모든 실행파일 빌드
# ------------------------------------------------
all: main_target main_new tracing_test test_bls381

# ------------------------------------------------
# ① 타겟 논문 구현
#    main_target.cpp + target.cpp
# ------------------------------------------------
main_target: main_target.o target.o
	$(CXX) -o $@ main_target.o target.o $(LDFLAGS)

main_target.o: main_target.cpp target.h
	$(CXX) $(CXXFLAGS) -c main_target.cpp

target.o: target.cpp target.h
	$(CXX) $(CXXFLAGS) -c target.cpp

# ------------------------------------------------
# ② 우리 스킴 구현 (BLS381)
#    main_new.cpp + new.cpp
# ------------------------------------------------
main_new: main_new.o new.o
	$(CXX) -o $@ main_new.o new.o $(LDFLAGS)

main_new.o: main_new.cpp new.h
	$(CXX) $(CXXFLAGS) -c main_new.cpp

# ------------------------------------------------
# ③ 트레이싱 성능 측정
#    tracing_test.cpp + new.cpp
# ------------------------------------------------
tracing_test: tracing_test.o new.o
	$(CXX) -o $@ tracing_test.o new.o $(LDFLAGS)

tracing_test.o: tracing_test.cpp new.h
	$(CXX) $(CXXFLAGS) -c tracing_test.cpp

# ------------------------------------------------
# ④ BLS381 곡선 sanity test
#    test_bls381.cpp (SQLite 불필요)
# ------------------------------------------------
test_bls381: test_bls381.o
	$(CXX) -o $@ test_bls381.o $(LDFLAGS_NO_SQL)

test_bls381.o: test_bls381.cpp
	$(CXX) $(CXXFLAGS) -c test_bls381.cpp

# ------------------------------------------------
# 공통 : BLS381 core
# ------------------------------------------------
new.o: new.cpp new.h
	$(CXX) $(CXXFLAGS) -c new.cpp

# ------------------------------------------------
# clean
# ------------------------------------------------
clean:
	rm -f *.o main_target main_new tracing_test test_bls381
