# bank-HackIT
bank is the binary; sploit3 is the exploit.
Uses offsets hardcoded for my libc. Alter before use.

# Short synopsis.
One byte overflow in create_account. 
Perform some chunk faking to create two overlapping chunks in two different fastbins.
Leak magic value and do it again to read stdin from imports table. 
Calculate addr of system and &__free_hook.
Repeat and change namesize to 0x200 or anything.
[Note that addr of content cannot be used for this purpose as edit() reads at most strlen(statement) bytes which would be 0 if we
did so.]
Overflow into next free chunk (in tcachebin) to overwrite *next to &__free_hook.
Overwrite free_hook with &system.
Free an account with statement = "/bin/sh\x00".
==> Shell.
