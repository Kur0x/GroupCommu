CC = g++
CFLAGS  = -Wall -O3 -std=c++0x 
OBJS = CA.o Cryptography.o ElGamalSignature.o RsaSignature.o
LIB = libmmx.a # 目标文件名 

%.o : %.cpp
	$(CC) $(CFLAGS) -c $< -o $@ -I../../include

# 3. 生成静态库文件
$(LIB) : $(OBJS)
	rm -f $@
	ar cr $@ $(OBJS)
	rm -f $(OBJS)
	mv *.a ../

.PHONY: clean
clean:
	-rm -f *.o *.a