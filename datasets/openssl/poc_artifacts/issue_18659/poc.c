#include <openssl/conf.h>
#include <openssl/ssl.h>

int main() {
  OPENSSL_init_ssl(0, NULL);
  OPENSSL_cleanup();
  CONF_modules_unload(1);
  return 0;
}
