# wolfSSL Top Family API Cards

Imported high-confidence staged cards in `api_card_v0` shape.


## DecodedCert

- family: `asn1_nested_boundary`

- confidence: `high`

- signature: `int wc_ParseCert(DecodedCert* cert, int type, int verify, void* cm);`

- status: structured raw knowledge, not vulnerability confirmation


## wc_FreeDecodedCert

- family: `asn1_nested_boundary`

- confidence: `high`

- signature: `wc_FreeDecodedCert(&decodedCert);`

- status: structured raw knowledge, not vulnerability confirmation


## wc_InitDecodedCert

- family: `asn1_nested_boundary`

- confidence: `high`

- signature: `\brief この関数は、入力されたDecodedCert構造体からDER形式の公開鍵を取得します。このAPIを呼び出す前に、ユーザーはwc_InitDecodedCert()とwc_ParseCert()を呼び出す必要があります。wc_InitDecodedCert()はDER/ASN.1エンコードされた証明書を受け入れます。PEM証明書をDERに変換するには、wc_InitDecodedCert()を呼び出す前にまずwc_CertP`

- status: structured raw knowledge, not vulnerability confirmation


## wc_ParseCert

- family: `asn1_nested_boundary`

- confidence: `high`

- signature: `ret = wc_ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL);`

- status: structured raw knowledge, not vulnerability confirmation


## wc_PKCS12_parse

- family: `pkcs_container_parsing`

- confidence: `high`

- signature: `WOLFSSL_ENTER("wc_PKCS12_parse");`

- status: structured raw knowledge, not vulnerability confirmation


## wc_PKCS7_Free

- family: `pkcs_container_parsing`

- confidence: `high`

- signature: `wc_PKCS7_Free(pkcs7);`

- status: structured raw knowledge, not vulnerability confirmation


## wc_PKCS7_Init

- family: `pkcs_container_parsing`

- confidence: `high`

- signature: `int ret = wc_PKCS7_Init(&pkcs7, NULL, INVALID_DEVID);`

- status: structured raw knowledge, not vulnerability confirmation


## wc_PKCS7_VerifySignedData

- family: `pkcs_container_parsing`

- confidence: `high`

- signature: `ret = wc_PKCS7_VerifySignedData(&pkcs7, pkcs7Buff, sizeof(pkcs7Buff));`

- status: structured raw knowledge, not vulnerability confirmation


## XFREE

- family: `secure_heap_state_lifecycle`

- confidence: `high`

- signature: `extern void XFREE(void *p, void* heap, int type);`

- status: structured raw knowledge, not vulnerability confirmation


## XMALLOC

- family: `secure_heap_state_lifecycle`

- confidence: `high`

- signature: `byte* der = (byte*)XMALLOC((8*1024), NULL, DYNAMIC_TYPE_CERT);`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_CTX_free

- family: `tls_protocol_state_lifecycle`

- confidence: `high`

- signature: `wolfSSL_CTX_free(ctx);`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_CTX_new

- family: `tls_protocol_state_lifecycle`

- confidence: `high`

- signature: `ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_CTX_set_verify

- family: `tls_protocol_state_lifecycle`

- confidence: `high`

- signature: `wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_accept

- family: `tls_protocol_state_lifecycle`

- confidence: `high`

- signature: `ret = wolfSSL_accept(ssl);`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_connect

- family: `tls_protocol_state_lifecycle`

- confidence: `high`

- signature: `\brief この関数は、バッファdataからszバイトをSSL接続sslに書き込みます。必要に応じて、wolfSSL_connect()またはwolfSSL_accept()によってハンドシェイクがまだ実行されていない場合、wolfSSL_write()はSSL/TLSセッションをネゴシエートします。(D)TLSv1.3を使用していてearly data機能がコンパイルされている場合、この関数はデータ送信が可能になるまでハンドシェイク`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_dtls

- family: `tls_protocol_state_lifecycle`

- confidence: `high`

- signature: `ret = wolfSSL_dtls(ssl);`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_dtls_set_peer

- family: `tls_protocol_state_lifecycle`

- confidence: `high`

- signature: `ret = wolfSSL_dtls_set_peer(ssl, &addr, sizeof(addr));`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_free

- family: `tls_protocol_state_lifecycle`

- confidence: `high`

- signature: `wolfSSL_free(ssl);`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_new

- family: `tls_protocol_state_lifecycle`

- confidence: `high`

- signature: `ssl = wolfSSL_new(ctx);`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_read

- family: `tls_protocol_state_lifecycle`

- confidence: `high`

- signature: `ret = wolfSSL_write(ssl) および wolfSSL_read(ssl);`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_shutdown

- family: `tls_protocol_state_lifecycle`

- confidence: `high`

- signature: `\brief この関数は、SSLセッションsslを使用してアクティブなSSL/TLS接続をシャットダウンします。この関数は、ピアに「close notify」アラートを送信しようと試みます。呼び出し側のアプリケーションは、ピアからの応答として「close notify」アラートが送信されるのを待つか、wolfSSL_shutdown()を直接呼び出した後に基盤となる接続をシャットダウンするか(リソースを節約するため)を選択できます。TL`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_use_PrivateKey_file

- family: `tls_protocol_state_lifecycle`

- confidence: `high`

- signature: `int wolfSSL_use_PrivateKey_file(WOLFSSL* ssl, const char* file, int format);`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_use_certificate_file

- family: `tls_protocol_state_lifecycle`

- confidence: `high`

- signature: `int wolfSSL_use_certificate_file(WOLFSSL* ssl, const char* file, int format);`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_write

- family: `tls_protocol_state_lifecycle`

- confidence: `high`

- signature: `ret = wolfSSL_write(ssl) および wolfSSL_read(ssl);`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_X509_free

- family: `x509_parsing`

- confidence: `high`

- signature: `wolfSSL_X509_free(x509);`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_X509_get_der

- family: `x509_parsing`

- confidence: `high`

- signature: `byte* x509Der = wolfSSL_X509_get_der(x509, outSz);`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_X509_get_issuer_name

- family: `x509_parsing`

- confidence: `high`

- signature: `name = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(x509), 0, 0);`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_X509_get_subject_name

- family: `x509_parsing`

- confidence: `high`

- signature: `name = wolfSSL_X509_get_subject_name(cert);`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_X509_load_certificate_file

- family: `x509_parsing`

- confidence: `high`

- signature: `x509 = wolfSSL_X509_load_certificate_file(cliCert, SSL_FILETYPE_PEM);`

- status: structured raw knowledge, not vulnerability confirmation


## wolfSSL_X509_verify

- family: `x509_parsing`

- confidence: `high`

- signature: `WOLFSSL_API int wolfSSL_X509_verify(WOLFSSL_X509* x509, WOLFSSL_EVP_PKEY* pkey);`

- status: structured raw knowledge, not vulnerability confirmation
