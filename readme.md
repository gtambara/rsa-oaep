To verify how the system works, simply type python main.py -h and the program will show you the options.
For the majority of them, there are default values set to files in 'key' folder.

All you absolyutly have to decide is the operation.

In any case, here are the options transcriped:

options:
  -h, --help            show this help message and exit
  --keysize KEYSIZE, -key KEYSIZE
                        initial size of rsa modulus n
  --prv_key_path, -prv  Path for private key to be used
  --pub_key_path, -pub  Path for public key to be used
  --encript_path, -enc  Path to message to be encripted
  --store_path, -str    Path to signed message to be stored
  --decript_path, -dec  Path to message to be decripted
  --output_path, -out   Path to save the decripted message
  --key_setup, -set     1 for key generating and 0 for key importing
  --operation {1,2,3,4,5}, -op {1,2,3,4,5}
                        1 for full test 2 for encription 3 for decription 4 for signing 5 for verifying signature