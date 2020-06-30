INCS-libpcap = -I /usr/include/ -I /usr/local/include/
LIBS-libpcap = -L /usr/lib/ -l:libpcap.so

none:
	@echo "\ndo nothing with no target"
	@echo "please input the format of \"make target\""
	@echo "input \"make help\" to understand the detailed information of targets\n"





help:
	@echo "\nthis is make help\n"
	
	@echo "cleaning targets"
	@echo "clean:			rm *.o files"
	@echo "distclean:		rm *.o *.exe files\n"
	
	@echo "compiling targets"
	@echo "libpcap-demo: 	compile libpcap demo\n"



libpcap-demo: start capture_package.o
	gcc ./bin/capture_package.o -o ./bin/capture_package $(LIBS-libpcap)
	@echo "\033[31m\n\n\tcompile successfully!\n\n\033[0m"

start:
	@echo "\033[32m\n\n\tstart compile!\n\n\033[33m"

capture_package.o: ./src/capture_package.c
	gcc -c -g $(INCS-libpcap) $(LIBS-libpcap) ./src/capture_package.c -o ./bin/capture_package.o
	@echo


clean:
	rm -rf ./bin/*.o
	rm -rf ./output/log/*
	rm -rf ./output/pcap_files/*

distclean:
	rm -rf ./bin/*
	rm -rf ./output/log/*
	rm -rf ./output/pcap_files/*

