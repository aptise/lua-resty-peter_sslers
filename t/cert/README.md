These Certificates and Keys are used for tests.

* example.com.cert + example.com.privkey
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

* test.example.com.cert + test.example.com.privkey
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

