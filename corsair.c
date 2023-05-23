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
#include <unistd.h>

typedef struct s_rsa
{
    BIGNUM *n; // modulus
    BIGNUM *e; // exponent
    BIGNUM *p; // first prime
    BIGNUM *q; // second prime
    BIGNUM *d; // private
    BIGNUM *pMinusOne; // p - 1
    BIGNUM *qMinusOne; // q - 1
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

    // https://linux.die.net/man/3/bn_dup
    // Extract the modulus and exponent from the RSA key
    trsa->n = BN_dup(RSA_get0_n(rsa));
    trsa->e = BN_dup(RSA_get0_e(rsa));
    printf("\33[32mmodulus :\33[0m\n");
    BN_print_fp(stdout,trsa->n);
    printf("\n");
    printf("\33[32mexponent :\33[0m\n");
    BN_print_fp(stdout,trsa->e);
    printf("\n");

    // https://www.openssl.org/docs/man1.0.2/man3/bn.html
    //  int BN_print_fp(FILE *fp, const BIGNUM *a);
    RSA_free(rsa);
}


/*
    https://manpages.debian.org/stretch/libssl-doc/RSA_set0_key.3ssl.en.html
    int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
    int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);
*/

RSA *generate_private_key(BIGNUM *e, BIGNUM *n, BIGNUM *p , BIGNUM *q, BIGNUM *d)
{
    RSA * privateKey = RSA_new();

    RSA_set0_key(privateKey,n,e,d);
    RSA_set0_factors(privateKey,p,q);
    return privateKey;
}

void    ft_leaks()
{
    system("leaks -q a.out");
}

int main(int ac, char **av)
{
    atexit(ft_leaks);
    if (ac != 5) {
        printf("Usage : ./corsair <pubCert1>.pem <pubCert2>.pem <msg1>.bin <msg2.bin>");
        return 1;
    }
    t_rsa *key1;
    t_rsa *key2;
    BIGNUM *commonPrime = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *phi1 = BN_new();
    BIGNUM *phi2 = BN_new();

    if (BN_dec2bn(&one,"1") == 0)
    {
        printf("BN_dec2bn failed to convert 1 to BN");
        exit(1);
    }
    key1 = malloc(sizeof(t_rsa));
    key2 = malloc(sizeof(t_rsa));
    // For the 'q' I use commonPrime for both, so no need to allocate, and for the 'n' and 'e' they get allocated by BN_dup(); inside store_n_e(); 
    key1->p = BN_new();
    key1->d = BN_new();
    key1->pMinusOne = BN_new();
    key1->qMinusOne = BN_new();

    key2->p = BN_new();
    key2->d = BN_new();
    key2->pMinusOne = BN_new();
    key2->qMinusOne = BN_new();
    store_n_e(av[1],key1);
    store_n_e(av[2],key2);

    // https://www.openssl.org/docs/man3.0/man3/BN_gcd.html
    // int BN_gcd(BIGNUM *r, BIGNUM *a, BIGNUM *b, BN_CTX *ctx); // calculates gcd(a,b), places the result in r
    // the fourth argument is a temporary struct used by BN to avoid repeated expense mem allocs
    // BN_CTX *BN_CTX_new(void);
    BN_CTX *tmp = BN_CTX_new();

    BN_gcd(commonPrime,key1->n,key2->n,tmp);
    
    // https://www.openssl.org/docs/man3.0/man3/BN_cmp.html
    // int BN_cmp(const BIGNUM *a, const BIGNUM *b);
    if (BN_cmp(commonPrime,one) == 1)
    {
        printf("\33[92m\nPrime in common :\33[0m\n");
        BN_print_fp(stdout,commonPrime);
    }
    else
    {
        printf("No primes in common, my job here is done, Bye ! :)\n");

        BN_free(key1->p);
        BN_free(key1->q);
        BN_free(key1->e);
        BN_free(key1->n);
        BN_free(key1->pMinusOne);
        BN_free(key1->qMinusOne);
        BN_free(key1->d);
        BN_free(phi1);


        BN_free(key2->p);
        BN_free(key2->q);
        BN_free(key2->e);
        BN_free(key2->n);
        BN_free(key2->pMinusOne);
        BN_free(key2->qMinusOne);
        BN_free(key2->d);
        BN_free(phi2);

        BN_CTX_free(tmp);
        BN_free(one);
        BN_free(commonPrime);
        free(key1);
        free(key2);
        exit(1);
    }
    // int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d, BN_CTX *ctx);
    BN_div(key1->p,NULL,key1->n,commonPrime,tmp);
    BN_div(key2->p,NULL,key2->n,commonPrime,tmp);

    // int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
    BN_sub(key1->pMinusOne,key1->p,one);
    BN_sub(key1->qMinusOne,commonPrime,one);

    BN_sub(key2->pMinusOne,key2->p,one);
    BN_sub(key2->qMinusOne,commonPrime,one);

    // int BN_mul(BIGNUM *r, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);
    BN_mul(phi1,key1->pMinusOne,key1->qMinusOne,tmp);
    BN_mul(phi2,key2->pMinusOne,key2->qMinusOne,tmp);

    // https://www.openssl.org/docs/man3.1/man3/BN_mod_inverse.html
    // BIGNUM *BN_mod_inverse(BIGNUM *r, BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

    BN_mod_inverse(key1->d,key1->e,phi1,tmp);
    BN_mod_inverse(key2->d,key2->e,phi2,tmp);
    // BN_print_fp(stdout,key1->d);
    // printf("\n");
    // BN_print_fp(stdout,key2->d);


    BIGNUM *c2 = BN_dup(commonPrime);
    RSA * privateKey1 = generate_private_key(key1->e,key1->n,key1->p,commonPrime,key1->d);
    RSA * privateKey2 = generate_private_key(key2->e,key2->n,key2->p,c2,key2->d);
    char to[1024];
    char from[1024];

    int fd = open(av[3],O_RDONLY);
    if (fd < 0){
        printf("Failed to open msg file.");
        exit(1);
    }
    int len1 = read(fd,from,1024);
    close(fd);
    // int RSA_private_decrypt(int flen, unsigned char *from, unsigned char *to, RSA *rsa, int padding);
    RSA_private_decrypt(len1,from,to,privateKey1,RSA_PKCS1_PADDING);
    printf("\n\33[94mDecrypted msg :\33[0m %s",to);

    fd = open(av[4],O_RDONLY);
    if (fd < 0){
        printf("Failed to open msg file.");
        exit(1);
    }
    len1 = read(fd,from,1024);
    close(fd);
    RSA_private_decrypt(len1,from,to,privateKey2,RSA_PKCS1_PADDING);
    printf("\33[94mDecrypted msg :\33[0m %s",to);

    // Clean up
    RSA_free(privateKey1);
    RSA_free(privateKey2);

    BN_free(key1->pMinusOne);
    BN_free(key1->qMinusOne);
    BN_free(phi1);


    BN_free(key2->pMinusOne);
    BN_free(key2->qMinusOne);
    BN_free(phi2);

    BN_CTX_free(tmp);
    BN_free(one);
    free(key1);
    free(key2);
    return 0;
}
