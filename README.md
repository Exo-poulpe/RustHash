## *RUSTHASH* ##

**RustHash** is a program for test hash in Rust.

### Installation ###

*This program work only for x64 OS*

Download the Rust source and compile then.

### Usage/Help ###
```
RustHash 0.0.3.1
Exo-poulpe
Rust hash test hash from wordlist

USAGE:
    RustHash [FLAGS] [OPTIONS]

FLAGS:
    -b, --benchmark          Test hash perfs
    -c                       Print number of password tested
        --disable-potfile    Disable potfile check
        --hardware-info      Print info hardware
    -h, --help               Print this message
    -v, --verbose            More verbose output
    -V, --version            Prints version information

OPTIONS:
        --detect-hash <DETECT>    Check if hash is valid
    -f, --file <FILE>             Set wordlist to use
    -m <METHODS>                  Set methods for hashing :
                                  1)    : MD5
                                  2)    : MD4
                                  3)    : SHA-1
                                  4)    : SHA-256
                                  5)    : SHA-512
    -t, --target <TARGET>         Set hashes to test (file or string)
```
### Exemple ###
For exemple : s
```
./RustHash.exe -t "1a79a4d60de6718e8e5b326e338ae533" -f lst.txt -m 1
```
With this command the hash "1a79a4d60de6718e8e5b326e338ae533::example" and use the wordlis lst.txt and with methods MD5

Result : 
```
wordlist use    : lst.txt
hash to find    : 1a79a4d60de6718e8e5b326e338ae533
Methods use     : MD5
===================================
Hash find : "example"
Time : 1.34s
```
### Benchmark ###
```
Methods use     : MD5
Hash number     : 1000000
===================================
Time elapsed    : 24.15s
Benchmark       : 41.415 KH/s
```
For benchmark RustHash test 1'000'000 MD5 hash (default)
