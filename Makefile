CXX = clang++
CC = clang
CXXFLAGS = -Wall -g -O2 -std=c++11 
CCFLAGS = -Wall -g -O2
INCLUDES = -I. -I./scamper-cvs-20111202c/scamper
LIBS = -lz  -lscamperfile
LDFLAGS = -L./scamper-cvs-20111202c/scamper
OBJS = topodata_parse2.o patricia.o
TARGET = topodata_parse2

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $(CXXFLAGS) $(OBJS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(OBJS)
	$(RM) $(TARGET)

.cc.o:
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) $<

.c.o:
	$(CC) -c $(CCFLAGS) $(INCLUDES) $<
