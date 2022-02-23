# https://crackmes.one/crackme/5feae16d33c5d4264e590154

import r2pipe


if __name__ == "__main__":

    searchForString = "what is the password"                        # Tell me what is the password!?!?!
    
    r2 = r2pipe.open("crackme.exe", flags=["-2"])                   # Open stream crackme.exe
    r2.cmd("aa")                                                    # Analyze crackme.exe 
    offset = r2.cmdj("/wj {}".format(searchForString))[0]           # Search the string "What is the password"
    offset = offset.get("offset")                                   # Get offset 
    breakpointAddr = r2.cmdj("axtj @ 0x{:x}".format(offset))[0]     # Search for xref from the offset
    breakpointAddr = breakpointAddr.get("from")                     # Get offset
    r2.cmd("db 0x{:x}".format(breakpointAddr))                      # Add breakpoint to the found offset
    r2.cmd("ood;3dc")                                               # Run

    while True:    
        esp = r2.cmdj("drj esp")                                    # Get value of ESP register. Returns as rsp ....?                                                 
        if esp == None:                                             # If list is empty exit
            exit()
                                          
        esp = esp.get("rsp") + 0x2F                                 # Add 0x2F to value of ESP to get the stack addr
        if(r2.cmd("s").strip() == "0x{:x}".format(breakpointAddr)): # Check current address is equal to address
            dec = r2.cmdj("pxj 12 @ {}".format(esp))                # Get value from stack and return list
            dec = "".join(chr(i) for i in dec)                      # Dec to ascii
            print("Hey pssst, the password is: {}".format(dec))     # Print password in console
        r2.cmd("s-;dc")                                             # Undo seek and continue

"""
Never worked with radare2 before but I fell in love.
It's a amazing framework to work with and to automate.

Tools used: 
    * radare2
    * r2pipe

Basically, store the generated password to esp stack in 0x2F.
Compare the user input with the generated password.
if not equal generate a new password. 

 |           0x004015b3      c644042f00     mov byte [esp + eax + 0x2f], 0 
 ........
 |           0x004015e8      89442404       mov dword [s2], eax         ; const char *s2                                     
 |           0x004015ec      8d44241b       lea eax, [s1]                                                                    
 |           0x004015f0      890424         mov dword [esp], eax        ; const char *s1                                     
 |           0x004015f3      e868260000     call sym._strcmp            ;[2] ; int strcmp(const char *s1, const char *s2)    
.........                                                        
 |       ,=< 0x00401601      7416           jne 0x401619                                                    

The 10 commands used in Radare2
    aaa
    iz
    axt 0x004050ed
    s 0x4015c4
    v
    db 0x4015c4
    ood
    3dc
    dr esp 
    px 12 @ 0x0061feff

python .\crackme.py 
Spawned new process with pid 10288, tid = 1168
File crackme.exe  reopened in read-write mode
hit breakpoint at: 0x4015c4
Hey pssst, the password is: 0Nq1Hg7Ho3Bm

Press enter to start

                ##################
                # CRACK ME DADDY #
                ##################

------------------------------------------------------------------------
what is the password :: 0Nq1Hg7Ho3Bm
congrats you got it!!, the password was really 0Nq1Hg7Ho3Bm

==> Process finished
"""