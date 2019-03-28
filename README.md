## *RUSTHASH* ##

**RustHash** is a program for test hash in Rust.

### Installation ###

*This program work only for x64 OS*

Download the Rust source and compile then.

### Usage/Help ###
```
RustHash 0.0.1.5
Exo-poulpe
Rust hash test hash from wordlist

USAGE:
    RustHash [FLAGS] [OPTIONS]

FLAGS:
    -b, --benchmark    Test hash perfs
    -c                 Show number of password tested
    -h, --help         Show this message
    -v, --verbose      More verbose output
    -V, --version      Prints version information

OPTIONS:
    -f, --file <FILE>        Set wordlist to use
    -m <METHODS>             Set methods for hashing :
                             1)         : MD5
                             2)         : SHA-1
                             3)         : SHA-256
                             4)         : SHA-512 (Not implemented)
    -t, --target <TARGET>    Set hash target for test
```
### Exemple ###
For exemple : 
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
For benchmark RustHash test 1'000'000 MD5 hash in a duration
