CPP=gcc
CSRCFLAGS=-pthread  -O3 
C_DBG=-Wall -Wextra -Wuninitialized -pedantic -g
OBJ= extalk.o scan.o

# k-debug: $(OBJ)
# 	$(CPP) -o $@ $^ $(C_DBG)

extalk: $(OBJ)
	$(CPP) -o $@ $^ $(CSRCFLAGS)

%.o: $.c
	$(CPP) $(CSRCFLAGS) -c $< -o $@
	
clean:
	rm *.o 
