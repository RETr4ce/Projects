# https://crackmes.one/crackme/5feff9b233c5d4264e5901c7

import r2pipe

if __name__ == "__main__":

    searchForString = "what_is_the_password"                                            # Search string

    r2 = r2pipe.open("crackme.exe", flags=["-2"])                                       # Open crackme.exe
    r2.cmd("aaa")                                                                       # Full analyze
    x = r2.cmdj("fs strings;fj")                                                        # Display Flags
    
    for offset in x:                                                                    # Check for seach string
        if searchForString in str(offset):
            offset = offset.get("offset")
            break

    breakPointAddr = r2.cmdj("axtj @ 0x{:x}".format(offset))[0]                         # Get href
    breakPointAddr = breakPointAddr.get("from")                                         # Get offset of href
    r2.cmd("db 0x{:x}".format(breakPointAddr))                                          # Set Breakpoint
    r2.cmd("ood;3dc")                                                                   # Debug; continue 3 times

    while True:                                                                         # Code has a loop of 10 times
        password = []
        esp = r2.cmdj("drj esp")                                                        # Get esp
        
        if esp == None:                                                                 # Method to see if we're still debugging. 
            exit()                                                                      # If not exit

        esp = esp.get("rsp") + 68                                                       # reference: 00401565     mov     eax, [esp+68h]
        if(r2.cmd("s").strip() == "0x{:x}".format(breakPointAddr)):                     # Check if current address is equal to address
            val = r2.cmdj("pxj 16 @ 0x{:x}".format(esp))                                # Get only 16 bytes from stack
            for i in val:                                                               # Put in array
                if i == 0:                                                              # If null byte is found break
                    break
                password.append(i)
        password = "".join(map(chr, password))                                          # Dec to ascii
        print("Psssst, the password is: {}".format(password))                           # Print Password in console
        r2.cmd("s-;dc")                                                                 # Undo seek and continue 


# Tools used:
#   Radare2
#   r2pipe
#   cutter
# ------- 
# Analyzing just for strings it shows that the crackme is expecting user input two times.
# First asking your name then the password. This made me glance with cutter 
# to look at the pseudocode. As just as I expected, it caesar cipher your name to be the password.
# But why is there a timer? 
# 
# The crackme does hint not to use spaces as it just ignores it. 
# 0x004014ff      movzx eax, byte [eax]
# 0x00401502      cmp al, 0x20       ; 32                                               // Compares if it's a space else ignore.
# 0x00401504      je 0x40150b
# ------- 
# Radare commands
# aaa                                                                                   // Analyze
# fs strings; f                                                                         // Show strings
# axt @ 0x004050f4                                                                      // Show href of str.___d___what_is_the_password_::
# db 0x401587                                                                           // Breakpoint on href
# db 0x4015da                                                                           // Breakpoint on congrats you got it!!
# ood; 3dc                                                                              // Run and continue 3 times
# dr esp                                                                                // Check ESP register
# px @ 0x0061feb0 + 68h                                                                 // Show the value where ESP points in the stack + 68h
# - offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
# 0x0061fef4  5f6c 5f00 feff ffff 08ff 6100 2d6f e775  _l_.......a.-o.u                 // The password is all up to the nullbyte
# dc                                                                                    // Continue
# -------     
# python .\crackme.py
# Spawned new process with pid 4016, tid = 7456
# File crackme.exe  reopened in read-write mode
# hit breakpoint at: 0x401587
# Psssst, the password is: _l_
# Press enter to start

#                 #####################
#                 # CRACK ME DADDY v2 #
#                 #####################

# what is your username(do not add spaces to make it easier) ::bob
#  -1-  what is the password ::_l_
# congrats you got it!!...
# the password was really '_l_'
#
# ==> Process finished
# -------  
# Keygen.CPP
#
#include <iostream>
#
# int main()
# {
#     int i;
#     int j;
#     int arr[255];                                                                     // Overflow!
#     char a;

#     std::string passwd;
#     passwd = "bob";                                                                   // Your password


#     for (i = 0; i < passwd.length(); ++i) {                                           // Convert string to int 
#         arr[i] = passwd[i];
#     }

#     for (j = 0; j <= passwd.length() && passwd[j]; ++j) {                             // Ceasar baby steps. 
#         passwd[j] -= passwd.length();
#         a = passwd[j];
#         std::cout << a;
#     }
#     std::cout;                                                                        // Output Passwd
# }
# -------
# keygen.py 
#
# if __name__ == "__main__":
#     arr = []                                                                          # Aaaaaarg, space pirate

#     passwd = "bob"                                                                    # Your password
#     for i in passwd:                                                                  # Convert string to int
#         arr.append(ord(i))

#     for y in range(len(arr)):                                                         # Ceasar baby steps
#         arr[y] -= len(passwd)

#     print("".join(map(chr, arr)))                                                     # Output password