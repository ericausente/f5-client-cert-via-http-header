# f5-client-cert-via-http-header

In scenarios where a f5's pool member is expecting the Client Certificate as an HTTP heade, we can delivering the client certificate via HTTP headers 


## Lab Reproduction Steps

1. Virtual Server Configuration: The Virtual Server was set to Client SSL in a two-way mode (see  K12140946: Configuring the BIG-IP system to perform two-way SSL authentication)
3. Certificate Generation: A Client certificate and key were generated in F5 (dummy) and imported as Client Certificate and Key, named "Client-cert".
  
To generate a dummy client certificate and key using OpenSSL and then import it into the F5 system, you would typically follow these steps:

```
openssl genrsa -out client.key 2048
```
This command creates a 2048-bit RSA private key and saves it in a file named client.key.


Create a Certificate Signing Request (CSR):
```
openssl req -new -key client.key -out client.csr
```

You'll be prompted to enter details for the certificate, such as the country, state, organization, etc. This information will be used in the certificate signing request (CSR) saved as client.csr.

Generate a Self-Signed Certificate:
```
openssl x509 -req -days 365 -in client.csr -signkey client.key -out client.crt
```

This command uses the CSR (client.csr) and the private key (client.key) to create a self-signed certificate (client.crt) valid for 365 days.

Importing the Certificate and Key in F5

- Access the F5 BIG-IP Configuration Utility
- Import the Certificate and Key:
        For the certificate (client.crt), choose Import... and upload the certificate file.
        For the private key (client.key), go to the SSL Key List and upload the key file.

- Name the Certificate and Key: When importing, name them as Client-cert or another identifiable name.

Configuring Client SSL Profile in F5
    Set the Profile to Require Client Certificates:
        Under Configuration, select Advanced.
        Set Client Certificate to Require.
        Under Trusted Certificate Authorities, select the previously imported Client-cert.

    Specify Once for Certificate Checking:
        This ensures the certificate is checked only once during the SSL handshake.

After completing these steps, the F5 system will be configured to use the generated dummy client certificate for SSL transactions, requiring client-side SSL certificates for authentication and establishing a trusted relationship with the client.



Attach the following Irule to the virtual server. 

```
when RULE_INIT {

   # Session timeout. Length of time (in seconds) to store the client cert in the session table.
   set ::session_timeout 3600

   # SSL::sessionid returns 64 0's if the session ID doesn't exist, so set a to check for this
   set ::null_sessionid [string repeat 0 64]
}
when CLIENTSSL_CLIENTCERT {

   #################################################
   # Need to first check if there is a cert and that it's valid
   # ...
   #################################################

   # Save the first cert in the client request
   set cert [SSL::cert 0]

   # Save the cert fields to a list
   set fields [X509::cert_fields $cert [SSL::verify_result] hash issuer serial sigalg subject subpubkey validity versionnum whole]
   log local0. "Client certificate fields - $fields"

   # Add the cert to the session table for use in subsequent HTTP requests.  Use the SSL session ID as the key.
   session add ssl [SSL::sessionid] [list $cert $fields] $::session_timeout
}
when HTTP_REQUEST {
    foreach aHeader [HTTP::header names] {
    log local0. "HTTP Request Headers: $aHeader: [HTTP::header value $aHeader]"
    }
   # Check if there is an existing SSL session ID and if the cert is in the session table
   if {[SSL::sessionid] ne $::null_sessionid && [session lookup ssl [SSL::sessionid]] ne ""}{

      # Insert SSL cert details in the HTTP headers
      HTTP::header insert [lindex [session lookup ssl [SSL::sessionid]] 1]

   } else {

      # Send a response back to the client indicating they didn't present a valid cert.
      HTTP::respond 200 content [subst {<html>Invalid request with SSL session ID [SSL::sessionid]</html>}]
   }
   
       foreach aHeader [HTTP::header names] {
    log local0. "HTTP Request Headers: $aHeader: [HTTP::header value $aHeader]"
    }
}
```


Copy Client Certificate and Key to the Client Machine: The client.crt (certificate) and client.key (private key) files are copied to the client machine.

Execute Curl Command: On the client machine, the following command is executed:
```
curl https://172.16.100.79 -lvk --cert client.crt --key client.key
```

This command sends a request to the F5 Virtual Server at 172.16.100.79. 
The options used are:
    -l: Enables location following.
    -v: Verbose mode.
    -k: Allows connections to SSL sites without certificates.
    --cert client.crt: Specifies the client certificate file.
    --key client.key: Specifies the client private key file.

Monitor the LTM Log: Simultaneously, the log file /var/log/ltm on the F5 server is monitored (typically using a command like tail -f /var/log/ltm) to observe real-time logging of the event.

Output of /var/log/ltm: 
````
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <CLIENTSSL_CLIENTCERT>: Client certificate fields - SSLClientCertStatus OK SSLClientCertHash 21:be:e2:91:fc:d1:c3:92:e6:fc:8d:ce:3a:dd:af:fa SSLClientCertIssuer {C=SG, ST=Singapore, L=Singapore, O=F5, OU=PS, CN=hell.example.com, emailAddress=ericausente@example.c\08\08.cpom} SSLClientCertSerialNumber f1:b4:ba:db:da:90:2f:79 SSLClientCertSignatureAlgorithm sha256WithRSAEncryption SSLClientCertSubject {C=SG, ST=Singapore, L=Singapore, O=F5, OU=PS, CN=hell.example.com, emailAddress=ericausente@example.c\08\08.cpom} SSLClientCertSubjectPublicKey {RSA 2048} SSLClientCertNotValidBefore {Dec  4 08:13:52 2023 GMT} SSLClientCertNotValidAfter {Dec  3 08:13:52 2024 GMT} SSLClientCertVersion 1 SSLClientCert {-----BEGIN CERTIFICATE----- MIIDrDCCApQCCQDxtLrb2pAveTANBgkqhkiG9w0BAQsFADCBlzELMAkGA1UEBhMC U0cxEjAQBgNVBAgMCVNpbmdhcG9yZTESMBAGA1UEBwwJU2luZ2Fwb3JlMQswCQYD VQQKDAJGNTELMAkGA1UECwwCUFMxGTAXBgNVBAMMEGhlbGwuZXhhbXBsZS5jb20x KzApBgkqhkiG9w0BCQEWHG


========================<<<HEADERS BEFORE INSERTING>>>>====================================
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: Host: 172.16.100.79
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: User-Agent: curl/7.65.0
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: Accept: */*
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: Host: 172.16.100.79
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: User-Agent: curl/7.65.0
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: Accept: */*
```

```
========================<<<HEADERS AFTER INSERTING>>>>====================================
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: SSLClientCertStatus: OK
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: SSLClientCertHash: 21:be:e2:91:fc:d1:c3:92:e6:fc:8d:ce:3a:dd:af:fa
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: SSLClientCertIssuer: C=SG, ST=Singapore, L=Singapore, O=F5, OU=PS, CN=hell.example.com, emailAddress=ericausente@example.c\08\08.cpom
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: SSLClientCertSerialNumber: f1:b4:ba:db:da:90:2f:79
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: SSLClientCertSignatureAlgorithm: sha256WithRSAEncryption
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: SSLClientCertSubject: C=SG, ST=Singapore, L=Singapore, O=F5, OU=PS, CN=hell.example.com, emailAddress=ericausente@example.c\08\08.cpom
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: SSLClientCertSubjectPublicKey: RSA 2048
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: SSLClientCertNotValidBefore: Dec  4 08:13:52 2023 GMT
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: SSLClientCertNotValidAfter: Dec  3 08:13:52 2024 GMT
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: SSLClientCertVersion: 1
Dec  4 09:20:36 afm1.eric.local info tmm[11477]: Rule /Common/ssl_irule_insert_cert <HTTP_REQUEST>: HTTP Request Headers: SSLClientCert: -----BEGIN CERTIFICATE-----   MIIDrDCCApQCCQDxtLrb2pAveTANBgkqhkiG9w0BAQsFADCBlzELMAkGA1UEBhMC   U0cxEjAQBgNVBAgMCVNpbmdhcG9yZTESMBAGA1UEBwwJU2luZ2Fwb3JlMQswCQYD   VQQKDAJGNTELMAkGA1UECwwCUFMxGTAXBgNVBAMMEGhlbGwuZXhhbXBsZS5jb20x   KzApBgkqhkiG9w0BCQEWHGVyaWNhdXNlbnRlQGV4YW1wbGUuYwgILmNwb20wHhcN   MjMxMjA0MDgxMzUyWhcNMjQxMjAzMDgxMzUyWjCBlzELMAkGA1UEBhMCU0cxEjAQ   BgNVBAgMCVNpbmdhcG9yZTESMBAGA1UEBwwJU2luZ2Fwb3JlMQswCQYDVQQKDAJG   NTELMAkGA1UECwwCUFMxGTAXBgNVBAMMEGhlbGwuZXhhbXBsZS5jb20xKzApBgkq   hkiG9w0BCQEWHGVyaWNhdXNlbnRlQGV4YW1wbGUuYwgILmNwb20wggEiMA0GCSqG   SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCq30EglVqplpRBjm62YEv5P5WzpAh4Zk/7   Jqfe7RA8HTyxRqr7ZPhJ7a5ocKiZx9ZTBzVFVtOcX4j+4S6gsvdcWfoR0vkBUrqS   iIYnYDci+AV5cHUqCRXiDil2Hxwsvbk9hDVAmjkDFflxEPkuoarqV3XIvCgNQl96   CjGYCzszsKWzxgp7uRoZf1G344c5s65cZl9d0r+GGtjs+AGIZHjDLsy80spHLt9k   7PTbFP35QaFSVgBetL2yZD87aVKn+pWPqpvKEWVCL35uaAh7yK/IhMgqMAsrPMdu
```

