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

// void    ft_leaks()
// {
//     system("leaks -q a.out");
// }

void store_n_e(char *keyfile, BIGNUM *n, BIGNUM *e)
{
    RSA* rsa = NULL;
    // Create a BIO object for file I/O
    printf("\33[34mAccessing file : \33[33m%s\33[0m\n",keyfile);
    BIO* bio = BIO_new_file(keyfile, "r");
    if (bio == NULL) {
        printf("\n\33[31mFailed to open the key file.\n\33[0m");
        exit(1);
    }

    // Load the public key from the file
    rsa = PEM_read_bio_RSA_PUBKEY(bio, &rsa, NULL, NULL);
    BIO_free(bio);
    if (rsa == NULL) {
        printf("\n\33[31mFailed to load the public key.\n\33[0m");
        exit(1);
    }

    BN_copy(n,RSA_get0_n(rsa));
    BN_copy(e,RSA_get0_e(rsa));
    printf("\33[32mmodulus :\33[0m\n");
    BN_print_fp(stdout,n);
    printf("\n");
    printf("\33[32mexponent :\33[0m\n");
    BN_print_fp(stdout,e);
    printf("\n");

    RSA_free(rsa);
}

RSA *construct_key(BIGNUM *e, BIGNUM *n, BIGNUM *p , BIGNUM *q, BIGNUM *d)
{
    RSA * privateKey = RSA_new();

    RSA_set0_key(privateKey,n,e,d);
    RSA_set0_factors(privateKey,p,q);
    return privateKey;
}


void    decrypt_file(char *filename, RSA *privateKey){
    char to[1024];
    char from[1024];

    int fd = open(filename,O_RDONLY);
    printf("\n\33[34mAccessing msg file : \33[33m%s\33[0m",filename);
    if (fd < 0){
        printf("\n\33[31mFailed to open msg file.\33[0m");
        exit(1);
    }
    int len1 = read(fd,from,1024);
    close(fd);
    if (RSA_private_decrypt(len1,from,to,privateKey,RSA_PKCS1_PADDING) == -1)
    {
        printf("\n\33[31mFailed to Decrypt the msg file.\n\33[0m");
        exit(1);
    }
    printf("\n\33[32mDecrypted msg :\33[0m %s",to);
}

int main(int ac, char **av)
{
    // atexit(ft_leaks);
    if (ac != 5) {
        printf("Usage : ./corsair <pubCert1>.pem <pubCert2>.pem <msg1>.bin <msg2.bin>");
        return 1;
    }
    /* First RSA key */
    BIGNUM *p1 = BN_new();
    BIGNUM *n1 = BN_new();
    BIGNUM *e1 = BN_new();
    BIGNUM *d1 = BN_new();
    BIGNUM *pMinusOne1 = BN_new();
    BIGNUM *qMinusOne1 = BN_new();

    /* Second RSA key */
    BIGNUM *p2 = BN_new();
    BIGNUM *n2 = BN_new();
    BIGNUM *e2 = BN_new();
    BIGNUM *d2 = BN_new();
    BIGNUM *pMinusOne2 = BN_new();
    BIGNUM *qMinusOne2 = BN_new();

    BIGNUM *commonPrime = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *phi1 = BN_new();
    BIGNUM *phi2 = BN_new();

    if (BN_dec2bn(&one,"1") == 0)
    {
        printf("BN_dec2bn failed to convert 1 to BN");
        exit(1);
    }
    store_n_e(av[1],n1,e1);
    store_n_e(av[2],n2,e2);
    printf("\33[96m----------------------------------------------------\33[0m");
    BN_CTX *tmp = BN_CTX_new();

    BN_gcd(commonPrime,n1,n2,tmp);
    
    if (BN_cmp(commonPrime,one) == 1) {
        printf("\33[92m\nPrime in common :\33[0m\n");
        BN_print_fp(stdout,commonPrime);
    }
    else {
        printf("\n\33[31mNo primes in common, my job here is done, Bye ! :)\33[0m\n");
        exit(0);
    }
    BN_div(p1,NULL,n1,commonPrime,tmp);
    BN_div(p2,NULL,n2,commonPrime,tmp);

    BN_sub(pMinusOne1,p1,one);
    BN_sub(qMinusOne1,commonPrime,one);

    BN_sub(pMinusOne2,p2,one);
    BN_sub(qMinusOne2,commonPrime,one);

    BN_mul(phi1,pMinusOne1,qMinusOne1,tmp);
    BN_mul(phi2,pMinusOne2,qMinusOne2,tmp);


    BN_mod_inverse(d1,e1,phi1,tmp);
    BN_mod_inverse(d2,e2,phi2,tmp);

    printf("\33[92m\nPrivate factor d1 :\33[0m\n");
    BN_print_fp(stdout,d1);
    printf("\33[92m\nPrivate factor d2 :\33[0m\n");
    BN_print_fp(stdout,d2);

    BIGNUM *commonPrime2 = BN_dup(commonPrime);
    RSA * privateKey1 = construct_key(e1,n1,p1,commonPrime,d1);
    RSA * privateKey2 = construct_key(e2,n2,p2,commonPrime2,d2);

    decrypt_file(av[3],privateKey1);
    decrypt_file(av[4],privateKey2);

    // Clean up
    RSA_free(privateKey1);
    RSA_free(privateKey2);

    BN_free(pMinusOne1);
    BN_free(qMinusOne1);
    BN_free(phi1);

    BN_free(pMinusOne2);
    BN_free(qMinusOne2);
    BN_free(phi2);

    BN_CTX_free(tmp);
    BN_free(one);
    return 0;
}

/*


    // https://www.openssl.org/docs/man3.1/man3/PEM_read_bio_RSA_PUBKEY.html

    https://www.openssl.org/docs/man1.1.1/man3/RSA_get0_key.html
    const BIGNUM *RSA_get0_n(const RSA *d);
    const BIGNUM *RSA_get0_e(const RSA *d);

    https://www.openssl.org/docs/man3.0/man3/BN_gcd.html
    int BN_gcd(BIGNUM *r, BIGNUM *a, BIGNUM *b, BN_CTX *ctx); // calculates gcd(a,b), places the result in r
    the fourth argument is a temporary struct used by BN to avoid repeated expense mem allocs
    BN_CTX *BN_CTX_new(void);

    https://www.openssl.org/docs/man3.0/man3/BN_cmp.html
    int BN_cmp(const BIGNUM *a, const BIGNUM *b);

    int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d, BN_CTX *ctx);

    int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

    int BN_mul(BIGNUM *r, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);

    https://www.openssl.org/docs/man3.1/man3/BN_mod_inverse.html
    BIGNUM *BN_mod_inverse(BIGNUM *r, BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

    https://manpages.debian.org/stretch/libssl-doc/RSA_set0_key.3ssl.en.html
    int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
    int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);

    int RSA_private_decrypt(int flen, unsigned char *from, unsigned char *to, RSA *rsa, int padding);

*/
