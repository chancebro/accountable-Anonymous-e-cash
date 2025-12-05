CXX = g++
CXXFLAGS = -I./mcl/include -DMCL_USE_BLS12_381=1 -O2 -g
LDFLAGS = ./mcl/lib/libmcl.a -lsqlite3 -lpthread

# 기본 : 모든 실행파일 빌드
all: old tracing_test main_new

# -------------------------------
# ① old  (옛날 버전 : main.cpp + tracing.cpp)
# -------------------------------
old: main.o tracing.o
	$(CXX) -o $@ main.o tracing.o $(LDFLAGS)

main.o: main.cpp tracing.h
	$(CXX) $(CXXFLAGS) -c main.cpp

tracing.o: tracing.cpp tracing.h
	$(CXX) $(CXXFLAGS) -c tracing.cpp

# -------------------------------
# ② tracing_test  (새 버전 : tracing_test.cpp + new.cpp)
#    ⚠ tracing.o 안 씀!
# -------------------------------
tracing_test: tracing_test.o new.o
	$(CXX) -o $@ tracing_test.o new.o $(LDFLAGS)

tracing_test.o: tracing_test.cpp new.h
	$(CXX) $(CXXFLAGS) -c tracing_test.cpp

# -------------------------------
# ③ main_new  (새 버전 : main_new.cpp + new.cpp)
# -------------------------------
main_new: main_new.o new.o
	$(CXX) -o $@ main_new.o new.o $(LDFLAGS)

main_new.o: main_new.cpp new.h
	$(CXX) $(CXXFLAGS) -c main_new.cpp

# -------------------------------
# 공통 : new.cpp (BLS381용 새 구현)
# -------------------------------
new.o: new.cpp new.h
	$(CXX) $(CXXFLAGS) -c new.cpp

# -------------------------------
# clean
# -------------------------------
clean:
	rm -f *.o old tracing_test main_new