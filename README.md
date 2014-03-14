traffana
========

Traffic analyser Tool

Compilation:
 Extract the tar in a folder.
 Go to the Folder and type 'make'

 Compilation can also be done by typing following command
 g++ -o traffana assign2.cpp  -lpcap -Wall

To Run:
traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ][-z tuple_mode]

-r --> Pcap File name
-i --> Deviece to live monitor
-T --> Epoch time (can be only integer)
-w --> Output  File Name
-v --> Verbose Mode
-z --> tuple Mode(Default two tuple)

Assumptions:

All other options except verbose if specified requires mandatory argument.If the arguemts are not supplied errors will thrown.

If epoch Time is not specified default value of 2 will be taken.
