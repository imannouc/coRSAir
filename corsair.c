#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct s_rsa
{
    BIGNUM *n; // modulus
    BIGNUM *e; // exponent
    BIGNUM *p; // first prime
    BIGNUM *q; // second prime
    BIGNUM *d; // private
} t_rsa;

void store_n_e(char *keyfile, t_rsa *trsa)
{
    RSA* rsa = NULL;
    // Create a BIO object for file I/O
    printf("\33[34mAccessing file : \33[33m%s\33[0m\n",keyfile);
    BIO* bio = BIO_new_file(keyfile, "r");
    if (bio == NULL) {
        printf("Failed to open the key file.\n");
        exit(1);
    }

    // Load the public key from the file
    rsa = PEM_read_bio_RSA_PUBKEY(bio, &rsa, NULL, NULL);
    // https://www.openssl.org/docs/man3.1/man3/PEM_read_bio_RSA_PUBKEY.html
    BIO_free(bio);

    if (rsa == NULL) {
        printf("Failed to load the public key.\n");
        exit(1);
    }
        // {
        //     FILE *out = stdout;
        //     RSA_print_fp(out, rsa, 0);
        // }
    // https://www.openssl.org/docs/man1.1.1/man3/RSA_get0_key.html
    // const BIGNUM *RSA_get0_n(const RSA *d);
    // const BIGNUM *RSA_get0_e(const RSA *d);

    // Extract the modulus and exponent from the RSA key
    trsa->n = RSA_get0_n(rsa);
    trsa->e = RSA_get0_e(rsa);
    // https://www.openssl.org/docs/man1.0.2/man3/bn.html
    //  int BN_print_fp(FILE *fp, const BIGNUM *a);
    printf("\33[32mmodulus :\33[0m\n");
    BN_print_fp(stdout,trsa->n);
    printf("\n");
    printf("\33[32mexponent :\33[0m\n");
    BN_print_fp(stdout,trsa->e);
    printf("\n");
    // RSA_free(rsa);
}

int main(int ac, char **av)
{
    t_rsa *key1;
    t_rsa *key2;
    BIGNUM *gcd = BN_new();
    // BIGNUM *mod_ing = BN_new();
    BIGNUM *one;

    if (BN_dec2bn(&one,"16") == 0)
    {
        printf("BN_dec2bn failed to convert 1 to BN");
        exit(1);
    }
    BN_print_fp(stdout,one);
    if (ac != 5) {
        printf("Usage : ./corsair <pubCert1>.pem <pubCert2>.pem <msg1>.bin <msg2.bin>");
        return 1;
    }
    key1 = malloc(sizeof(t_rsa));
    key2 = malloc(sizeof(t_rsa));

    store_n_e(av[1],key1);
    store_n_e(av[2],key2);


    // https://www.openssl.org/docs/man3.0/man3/BN_gcd.html
    // int BN_gcd(BIGNUM *r, BIGNUM *a, BIGNUM *b, BN_CTX *ctx); // calculates gcd(a,b), places the result in r
    // the fourth argument is a temporary struct used by BN to avoid repeated expense mem allocs
    // BN_CTX *BN_CTX_new(void);
    BN_CTX *tmp = BN_CTX_new();

    BN_gcd(gcd,key1->n,key2->n,tmp);
    BN_print_fp(stdout,gcd);
    
    // https://www.openssl.org/docs/man3.0/man3/BN_cmp.html
    // int BN_cmp(const BIGNUM *a, const BIGNUM *b);
    if (BN_cmp(gcd,one) == 1)
        printf("GOTCHAAAA");
    else{
        printf("No primes in common, my job here is done, Bye ! :)");
        // Clean up
        return 0;
    }
    

    // https://www.openssl.org/docs/man3.1/man3/BN_mod_inverse.html
    // BIGNUM *BN_mod_inverse(BIGNUM *r, BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

    // BN_mod_inverse()

    // Clean up
    free(key1);
    free(key2);
    // RSA_free(rsa);
    return 0;
}
