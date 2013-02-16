### AES and CBC ArrayBuffer

This is a JavaScript AES and CBC implementation using ArrayBuffer. Why would you want that you might ask and the reason is that I wanted to do AES CBC crypto in a Chrome extension. I also wanted to make it resonable fast so the code might look a bit weird and it is also only optimized for Chrome v8.

Note that if you read this in a future when the [WebCrypto standard](http://www.w3.org/2012/webcrypto/WebCryptoAPI/) is available in all browser you need to support I suggest that you use that instead.

### Performance

2008 MacBook, Chrome 24, 2 GHz Core 2 Duo, 1067Mhz DDR3:  
Encrypt ~12.2 MB/s, Decrypt ~8.4 MB/s

2011 MacBook Air, Chrome 24, 1.5 GHz Core i5, 1333Mhz DDR3:  
Encrypt ~17.5 MB/s, Decrypt ~12.0 MB/s

If you want to benchmark yourself you can check the "CBC AES-128 Benchmark" test case in
the [unit tests](http://wader.github.com/aes-arraybuffer/tests.html).

### Usage

```JavaScript
// make sure both aes.js and crypto.js is included  
var iv = new Uint8Array([
  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
]);
var key = new Uint8Array([
  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
]);
var input = new Uint8Array(123456);

// pad input to be AES block size aligned and then encrypt  
var encrypted = Crypto.encrypt_aes_cbc(Crypto.pkcs_pad(input.buffer), key.buffer, iv.buffer);

// decrypt and then remove pad bytes
var decrypted = Crypto.pkcs_unpad(Crypto.decrypt_aes_cbc(encrypted, key.buffer, iv.buffer));

// decrypted is now a ArrayBuffer with same bytes as in input
```

### Possible improvements

Test if inverse equivalent cipher is faster. [crypto-js AES](http://crypto-js.googlecode.com/svn/tags/3.1/src/aes.js) seems to use that but haven't benchmarked their code yet.

