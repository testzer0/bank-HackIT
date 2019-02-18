# bank-HackIT
bank is the binary; sploit3 is the exploit.
Uses offsets hardcoded for my libc. Alter before use.

# Short synopsis.
One byte overflow in create_account. 
Perform some chunk faking to create two overlapping chunks in two different fastbins.
Leak magic value and do it again to read stdin@got.plt.
Repeat and change namesize to 0x200 or anything.
Overflow into next free chunk (in tcachebin) to overwrite *next to &__free_hook.
Overwrite free_hook with &system.
Free an account with statement = "/bin/sh\x00".
==> Shell.
