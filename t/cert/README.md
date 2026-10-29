These Certificates and Keys are used for tests.

* example.com.crt + example.com.key
  * self signed certificate
  * covers example.com
  * `openssl req -newkey rsa:2048 -nodes -keyout example.com.key -x509 -days 365000 -out example.com.crt`
  * > Country Name (2 letter code) [AU]:US
    > State or Province Name (full name) [Some-State]:
    > Locality Name (eg, city) []:
    > Organization Name (eg, company) [Internet Widgits Pty Ltd]:Aptise     
    > Organizational Unit Name (eg, section) []:PeterSSLers        
    > Common Name (e.g. server FQDN or YOUR name) []:example.com
    > Email Address []:devnull@example.com

* test.example.com.crt + test.example.com.key
  * self signed certificate
  * covers test.example.com
  * `openssl req -newkey rsa:2048 -nodes -keyout test.example.com.key -x509 -days 365000 -out test.example.com.crt`
  * > Country Name (2 letter code) [AU]:US
    > State or Province Name (full name) [Some-State]:
    > Locality Name (eg, city) []:
    > Organization Name (eg, company) [Internet Widgits Pty Ltd]:Aptise     
    > Organizational Unit Name (eg, section) []:PeterSSLers        
    > Common Name (e.g. server FQDN or YOUR name) []:test.example.com
    > Email Address []:devnull@example.com

* _all.crt
  * all certificates
  * used for `lua_ssl_trusted_certificate` in tests
  * `cat example.com.crt test.example.com.crt wildcard.test.example.com.crt > _all.crt`
  

* wildcard.test.example.com.crt + wildcard.test.example.com.key
  * self-signed test identity covering `*.test.example.com` through a SAN
  * permits unique run/worker SNI names while keeping TLS hostname verification enabled
  * included in `_all.crt` for client verification in the integration suite
  * generated for tests with:

    ```sh
    openssl req -x509 -newkey rsa:2048 -nodes -days 36500 \
        -subj '/CN=*.test.example.com' \
        -addext 'subjectAltName=DNS:*.test.example.com' \
        -keyout wildcard.test.example.com.key -out wildcard.test.example.com.crt
    ```
