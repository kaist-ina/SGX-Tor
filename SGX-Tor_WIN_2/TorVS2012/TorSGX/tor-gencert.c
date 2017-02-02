/* Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

#include <errno.h>
#if 0
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#endif

#include "compat.h"
#include "util.h"
#include "torlog.h"
#include "crypto.h"
#include "address.h"
#include "util_format.h"
#include "tor-gencert.h"

#define IDENTITY_KEY_BITS 3072
#define SIGNING_KEY_BITS 2048
#define DEFAULT_LIFETIME 12

char *sgx_signing_key;
char *sgx_identity_key;
char *sgx_authority_certificate;

/* These globals are set via command line options. */
int months_lifetime = DEFAULT_LIFETIME;
char *address = NULL;

char *passphrase = NULL;
size_t passphrase_len = 0;

EVP_PKEY *identity_key = NULL;
EVP_PKEY *signing_key = NULL;

/* XXXX copied from crypto.c */
static void
crypto_log_errors(int severity, const char *doing)
{
  unsigned long err;
  const char *msg, *lib, *func;
  while ((err = ERR_get_error()) != 0) {
    msg = (const char*)ERR_reason_error_string(err);
    lib = (const char*)ERR_lib_error_string(err);
    func = (const char*)ERR_func_error_string(err);
    if (!msg) msg = "(null)";
    if (!lib) lib = "(null)";
    if (!func) func = "(null)";
    if (doing) {
      tor_log(severity, LD_CRYPTO, "crypto error while %s: %s (in %s:%s)",
              doing, msg, lib, func);
    } else {
      tor_log(severity, LD_CRYPTO, "crypto error: %s (in %s:%s)",
              msg, lib, func);
    }
  }
}

static void
clear_passphrase(void)
{
  if (passphrase) {
    memwipe(passphrase, 0, passphrase_len);
    tor_free(passphrase);
  }
}

/** Read the command line options from <b>argc</b> and <b>argv</b>,
 * setting global option vars as needed.
 */
static int
parse_commandline(const char *_month, const char *_addr)
{
	uint32_t addr;
  uint16_t port;
  char b[INET_NTOA_BUF_LEN];
  struct in_addr in;
	if(_month != NULL) {
		months_lifetime = atoi(_month);
		if (months_lifetime > 24 || months_lifetime < 0) {
			printf("Lifetime (in months) was out of range.\n");
			return 1;
		}
	}
	if(_addr != NULL) {
    if (addr_port_lookup(LOG_ERR, _addr, NULL, &addr, &port)<0)
      return 1;
    in.s_addr = htonl(addr);
    tor_inet_ntoa(&in, b, sizeof(b));
    tor_asprintf(&address, "%s:%d", b, (int)port);
	}  
  return 0;
}

static RSA *
generate_key(int bits)
{
  RSA *rsa = NULL;
  crypto_pk_t *env = crypto_pk_new();
  if (crypto_pk_generate_key_with_bits(env,bits)<0)
    goto done;
  rsa = crypto_pk_get_rsa_(env);
  rsa = RSAPrivateKey_dup(rsa);
 done:
  crypto_pk_free(env);
  return rsa;
}

/** Try to read the identity key from <b>identity_key_file</b>.  If no such
 * file exists and create_identity_key is set, make a new identity key and
 * store it.  Return 0 on success, nonzero on failure.
 */
static char *
generate_identity_key(void)
{
  RSA *key;
	BIO *b;
	BUF_MEM *buf;
	char *retv;

  log_notice(LD_GENERAL, "Generating %d-bit RSA identity key.",
              IDENTITY_KEY_BITS);
  if (!(key = generate_key(IDENTITY_KEY_BITS))) {
    log_err(LD_GENERAL, "Couldn't generate identity key.");
    crypto_log_errors(LOG_ERR, "Generating identity key");
    return NULL;
  }
  identity_key = EVP_PKEY_new();
  if (!(EVP_PKEY_assign_RSA(identity_key, key))) {
    log_err(LD_GENERAL, "Couldn't assign identity key.");
    return NULL;
  }

	b = BIO_new(BIO_s_mem());
	if (!b)
		return NULL;

  /* Write the key to the file.  If passphrase is not set, takes it from
    * the terminal. */
  if (!PEM_write_bio_PKCS8PrivateKey_nid(b, identity_key,
									NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
									passphrase, (int)passphrase_len,
									NULL, NULL)) {
    crypto_log_errors(LOG_ERR, "Writing identity key");
    return NULL;
  }
	BIO_get_mem_ptr(b, &buf);  
	(void)BIO_set_close(b, BIO_NOCLOSE); /* so BIO_free doesn't free buf */
	buf->data[buf->length] = '\0';
	retv = tor_strdup(buf->data);

	BIO_free(b);	
	BUF_MEM_free(buf);
 
  return retv;
}

/** Generate a new signing key and write it to disk.  Return 0 on success,
 * nonzero on failure. */
static char *
generate_signing_key(void)
{
  RSA *key;
	BIO *b;
	BUF_MEM *buf;
	char *retv;

  log_notice(LD_GENERAL, "Generating %d-bit RSA signing key.",
             SIGNING_KEY_BITS);
  if (!(key = generate_key(SIGNING_KEY_BITS))) {
    log_err(LD_GENERAL, "Couldn't generate signing key.");
    crypto_log_errors(LOG_ERR, "Generating signing key");
    return NULL;
  }
  signing_key = EVP_PKEY_new();
  if (!(EVP_PKEY_assign_RSA(signing_key, key))) {
    log_err(LD_GENERAL, "Couldn't assign signing key.");
    return NULL;
  }

	b = BIO_new(BIO_s_mem());
	if (!b)
    return NULL;

  /* Write signing key with no encryption. */
  if (!PEM_write_bio_RSAPrivateKey(b, key, NULL, NULL, 0, NULL, NULL)) {
    crypto_log_errors(LOG_WARN, "writing signing key");
    return NULL;
  }

	BIO_get_mem_ptr(b, &buf);  
	(void)BIO_set_close(b, BIO_NOCLOSE); /* so BIO_free doesn't free buf */
	buf->data[buf->length] = '\0';
	retv = tor_strdup(buf->data);

	BIO_free(b);	
	BUF_MEM_free(buf);

  return retv;
}

/** Encode <b>key</b> in the format used in directory documents; return
 * a newly allocated string holding the result or NULL on failure. */
static char *
key_to_string(EVP_PKEY *key)
{
  BUF_MEM *buf;
  BIO *b;
  RSA *rsa = EVP_PKEY_get1_RSA(key);
  char *result;
  if (!rsa)
    return NULL;

  b = BIO_new(BIO_s_mem());
  if (!PEM_write_bio_RSAPublicKey(b, rsa)) {
    crypto_log_errors(LOG_WARN, "writing public key to string");
    return NULL;
  }

  BIO_get_mem_ptr(b, &buf);
  (void) BIO_set_close(b, BIO_NOCLOSE);
  BIO_free(b);
  result = (char *)tor_malloc(buf->length + 1);
  memcpy(result, buf->data, buf->length);
  result[buf->length] = 0;
  BUF_MEM_free(buf);

  return result;
}

/** Set <b>out</b> to the hex-encoded fingerprint of <b>pkey</b>. */
static int
get_fingerprint(EVP_PKEY *pkey, char *out)
{
  int r = 1;
  crypto_pk_t *pk = crypto_new_pk_from_rsa_(EVP_PKEY_get1_RSA(pkey));
  if (pk) {
    r = crypto_pk_get_fingerprint(pk, out, 0);
    crypto_pk_free(pk);
  }
  return r;
}

/** Set <b>out</b> to the hex-encoded fingerprint of <b>pkey</b>. */
static int
get_digest(EVP_PKEY *pkey, char *out)
{
  int r = 1;
  crypto_pk_t *pk = crypto_new_pk_from_rsa_(EVP_PKEY_get1_RSA(pkey));
  if (pk) {
    r = crypto_pk_get_digest(pk, out);
    crypto_pk_free(pk);
  }
  return r;
}

/** Generate a new certificate for our loaded or generated keys, and write it
 * to disk.  Return 0 on success, nonzero on failure. */
static char *
generate_certificate(void)
{
  char buf[8192];
  time_t now = time(NULL);
  struct tm tm;
  char published[ISO_TIME_LEN+1];
  char expires[ISO_TIME_LEN+1];
  char id_digest[DIGEST_LEN];
  char fingerprint[FINGERPRINT_LEN+1];
  char *ident = key_to_string(identity_key);
  char *signing = key_to_string(signing_key);
  size_t signed_len;
  char digest[DIGEST_LEN];
  char signature[1024]; /* handles up to 8192-bit keys. */
  int r;

  get_fingerprint(identity_key, fingerprint);
  get_digest(identity_key, id_digest);

  tor_localtime_r(&now, &tm);
  tm.tm_mon += months_lifetime;

  format_iso_time(published, now);
  format_iso_time(expires, mktime(&tm));

  tor_snprintf(buf, sizeof(buf),
               "dir-key-certificate-version 3"
               "%s%s"
               "\nfingerprint %s\n"
               "dir-key-published %s\n"
               "dir-key-expires %s\n"
               "dir-identity-key\n%s"
               "dir-signing-key\n%s"
               "dir-key-crosscert\n"
               "-----BEGIN ID SIGNATURE-----\n",
               address?"\ndir-address ":"", address?address:"",
               fingerprint, published, expires, ident, signing
               );
  tor_free(ident);
  tor_free(signing);

  /* Append a cross-certification */
  r = RSA_private_encrypt(DIGEST_LEN, (unsigned char*)id_digest,
                          (unsigned char*)signature,
                          EVP_PKEY_get1_RSA(signing_key),
                          RSA_PKCS1_PADDING);
  signed_len = strlen(buf);
  base64_encode(buf+signed_len, sizeof(buf)-signed_len, signature, r,
                BASE64_ENCODE_MULTILINE);

  strlcat(buf,
          "-----END ID SIGNATURE-----\n"
          "dir-key-certification\n", sizeof(buf));

  signed_len = strlen(buf);
  SHA1((const unsigned char*)buf,signed_len,(unsigned char*)digest);

  r = RSA_private_encrypt(DIGEST_LEN, (unsigned char*)digest,
                          (unsigned char*)signature,
                          EVP_PKEY_get1_RSA(identity_key),
                          RSA_PKCS1_PADDING);
  strlcat(buf, "-----BEGIN SIGNATURE-----\n", sizeof(buf));
  signed_len = strlen(buf);
  base64_encode(buf+signed_len, sizeof(buf)-signed_len, signature, r,
                BASE64_ENCODE_MULTILINE);
  strlcat(buf, "-----END SIGNATURE-----\n", sizeof(buf));

  return tor_strdup(buf);
}

/** Entry point to tor-gencert */
char *
start_gencert(const char *_month, const char *_addr)
{
  int fd;
	char *retv = NULL;
  init_logging(1);

  /* Don't bother using acceleration. */
  if (crypto_global_init(0, NULL, NULL)) {
    printf("Couldn't initialize crypto library.\n");
    return -1;
  }
  if (crypto_seed_rng()) {
    printf("Couldn't seed RNG.\n");
    goto done;
  }

	passphrase = tor_strdup("inatestpasswd");
	passphrase_len = strlen(passphrase);

  if (parse_commandline(_month, _addr))
    goto done;
  if ((sgx_identity_key = generate_identity_key()) == NULL)
    goto done;  
  if ((sgx_signing_key = generate_signing_key()) == NULL)
    goto done;
  if ((sgx_authority_certificate = generate_certificate()) == NULL)
    goto done;
//	printf("authority_certificate = %s\n", sgx_authority_certificate);
	
	fd = sgx_open("authority_signing_key", O_CREAT | O_TRUNC, 0);
	if(sgx_write(fd, sgx_signing_key, strlen(sgx_signing_key)+1) < 0)
		goto done;
	sgx_close(fd);
	fd = sgx_open("authority_identity_key", O_CREAT | O_TRUNC, 0);
	if(sgx_write(fd, sgx_identity_key, strlen(sgx_identity_key)+1) < 0)
		goto done;
	sgx_close(fd);
	fd = sgx_open("authority_certificate", O_CREAT | O_TRUNC, 0);
	if(sgx_write(fd, sgx_authority_certificate, strlen(sgx_authority_certificate)+1) < 0)
		goto done;

	sgx_close(fd);
	retv = tor_strdup(sgx_authority_certificate);

 done:
  clear_passphrase();
  if (identity_key)
    EVP_PKEY_free(identity_key);
  if (signing_key)
    EVP_PKEY_free(signing_key);
  tor_free(address);

  crypto_global_cleanup();
	
  return retv;
}

