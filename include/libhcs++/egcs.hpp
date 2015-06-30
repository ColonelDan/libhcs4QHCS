/**
 * @file egcs.h
 *
 * The ElGamal scheme is a scheme which provides homormophic multiplication.
 * It is usually used with some padding scheme similar to RSA. This
 * implementation only provides unpadded values to exploit this property.
 *
 * Due to the nature of the ciphertext, this implementation provides a
 * unique type for the ciphertext, rather than just using gmp mpz_t types.
 * These can be used with the provided initialisation functions, and should
 * be freed on program termination.
 *
 * All mpz_t values can be alises unless otherwise stated.
 */

#ifndef HCS_EGCS_HPP
#define HCS_EGCS_HPP

#include <gmpxx.h>
#include "rand.hpp"

namespace hcs {
namespace egcs {

class cipher {

private:
    egcs_cipher *c;

public:
    cipher() {
        c = egcs_init_cipher();
    }

    ~cipher() {
        egcs_free_cipher(c);
    }

    egcs_cipher* as_ptr() {
        return c;
    }

    clear() {
        egcs_clear_cipher(c);
    }
};

class public_key {

private:
    egcs_public_key *pk;
    hcs::rand *hr;

public:
    public_key(hcs::rand &hr_) {
        pk = egcs_init_public_key();
        hr = &hr_;
        hr->inc_refcount();
    }

    ~public_key() {
        egcs_free_public_key(pk);
        hr->dec_refcount();
    }

    egcs_public_key* as_ptr() {
        return pk;
    }

    hcs_rand* get_rand() {
        return hr->as_ptr();
    }

    /* Encryption functions acting on a key */
    void encrypt(cipher &rop, mpz_class &op) {
        egcs_encrypt(pk, hr->as_ptr(), rop.as_ptr(), op.get_mpz_t());
    }

    void ee_mul(cipher &rop, cipher &c1, cipher &c2) {
        egcs_ee_mul(pk, rop.as_ptr(), c1.as_ptr(), c2.as_ptr());
    }

    void clear() {
        egcs_clear_public_key(pk);
    }
};


class private_key {

private:
    egcs_private_key *vk;
    hcs::rand *hr;

public:
    private_key(hcs::rand &hr_) {
        vk = egcs_init_private_key();
        hr = &hr_;
        hr->inc_refcount();
    }

    ~private_key() {
        egcs_free_private_key(vk);
        hr->dec_refcount();
    }

    egcs_private_key* as_ptr() {
        return vk;
    }

    hcs_rand* get_rand() {
        return hr->as_ptr();
    }

    /* Encryption functions acting on a key */
    void decrypt(mpz_class &rop, egcs_cipher &op) {
        egcs_decrypt(vk, rop.get_mpz_t(), op.as_ptr());
    }

    void clear() {
        egcs_clear_private_key(pk);
    }
};

inline void generate_key_pair(public_key &pk, private_key &vk,
        const unsigned long bits) {
    egcs_generate_key_pair(pk.as_ptr(), vk.as_ptr(), pk.get_rand(), bits);
}

}
}

