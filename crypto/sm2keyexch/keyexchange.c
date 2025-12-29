#include "keyexchange.h"

int SM2_get_public_key_data(EC_KEY* ec_key, unsigned char* out, size_t* outlen)
{
    int ret = 0;
    const EC_GROUP* group;
    BN_CTX* bn_ctx = NULL;
    BIGNUM* p;
    BIGNUM* x;
    BIGNUM* y;
    int nbytes;
    size_t len;

    if (!ec_key || !outlen || !(group = EC_KEY_get0_group(ec_key))) {
        return 0;
    }

    nbytes = (EC_GROUP_get_degree(group) + 7) / 8;
    len = nbytes * 6;

    if (!out) {
        *outlen = len;
        return 1;
    }
    if (*outlen < len) {
        return 0;
    }

    if (!(bn_ctx = BN_CTX_new())) {
        goto  end;
    }

    BN_CTX_start(bn_ctx);
    p = BN_CTX_get(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    y = BN_CTX_get(bn_ctx);
    if (!y) {
        goto end;
    }

    memset(out, 0, len);

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
        if (!EC_GROUP_get_curve_GFp(group, p, x, y, bn_ctx)) {
            goto end;
        }
    }
    else {
        if (!EC_GROUP_get_curve_GF2m(group, p, x, y, bn_ctx)) {
            goto end;
        }
    }

    BN_bn2bin(x, out + nbytes - BN_num_bytes(x));
    out += nbytes;

    if (!BN_bn2bin(y, out + nbytes - BN_num_bytes(y))) {
        goto end;
    }
    out += nbytes;

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
        if (!EC_POINT_get_affine_coordinates_GFp(group,
            EC_GROUP_get0_generator(group), x, y, bn_ctx)) {
            goto end;
        }
    }
    else {
        if (!EC_POINT_get_affine_coordinates_GF2m(group,
            EC_GROUP_get0_generator(group), x, y, bn_ctx)) {
            goto end;
        }
    }

    if (!BN_bn2bin(x, out + nbytes - BN_num_bytes(x))) {
        goto end;
    }
    out += nbytes;

    if (!BN_bn2bin(y, out + nbytes - BN_num_bytes(y))) {
        goto end;
    }
    out += nbytes;

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
        if (!EC_POINT_get_affine_coordinates_GFp(group,
            EC_KEY_get0_public_key(ec_key), x, y, bn_ctx)) {
            goto end;
        }
    }
    else {
        if (!EC_POINT_get_affine_coordinates_GF2m(group,
            EC_KEY_get0_public_key(ec_key), x, y, bn_ctx)) {
            goto end;
        }
    }

    if (!BN_bn2bin(x, out + nbytes - BN_num_bytes(x))) {
        goto end;
    }
    out += nbytes;

    if (!BN_bn2bin(y, out + nbytes - BN_num_bytes(y))) {
        goto end;
    }

    *outlen = len;
    ret = 1;

end:
    if (bn_ctx) {
        BN_CTX_end(bn_ctx);
    }
    BN_CTX_free(bn_ctx);
    return ret;
}

int SM2_compute_id_digest(const EVP_MD* md, const char* id, size_t idlen,unsigned char* out, size_t* outlen, EC_KEY* ec_key)
{   
    int ret = 0;
    EVP_MD_CTX* md_ctx = NULL;
    unsigned char idbits[2];
    unsigned char pkdata[((661+7)/8+1)*6];
    unsigned int len;
    size_t size;

    if (!md || !id || idlen <= 0 || !outlen || !ec_key) {
        return 0;
    }

    if (strlen(id) != idlen) {
        return 0;
    }
    if (idlen > 65535/8 || idlen <= 0) {
        return 0;
    }

    if (!out) {
        *outlen = EVP_MD_size(md);
        return 1;
    }
    if (*outlen < (size_t)EVP_MD_size(md)) {
        return 0;
    }

    size = sizeof(pkdata);
    if (!SM2_get_public_key_data(ec_key, pkdata, &size)) {
        goto end;
    }

    idbits[0] = ((idlen * 8) >> 8) % 256;
    idbits[1] = (idlen * 8) % 256;

    len = EVP_MD_size(md);

    if (!(md_ctx = EVP_MD_CTX_new())
        || !EVP_DigestInit_ex(md_ctx, md, NULL)
        || !EVP_DigestUpdate(md_ctx, idbits, sizeof(idbits))
        || !EVP_DigestUpdate(md_ctx, id, idlen)
        || !EVP_DigestUpdate(md_ctx, pkdata, size)
        || !EVP_DigestFinal_ex(md_ctx, out, &len)) {
        goto end;
    }

    *outlen = len;
    ret = 1;

end:
    EVP_MD_CTX_free(md_ctx);
    return ret;
}

void SM2_KAP_CTX_cleanup(SM2_KAP_CTX* ctx)
{
    if (ctx) {
        EC_KEY_free(ctx->ec_key);
        EC_KEY_free(ctx->remote_pubkey);

        BN_CTX_free(ctx->bn_ctx);
        BN_free(ctx->two_pow_w);
        BN_free(ctx->order);
        BN_free(ctx->t);
        EC_POINT_free(ctx->point);

        memset(ctx, 0, sizeof(*ctx));
    }
}

int SM2_KAP_CTX_init(SM2_KAP_CTX* ctx, EC_KEY* ec_key, const char* id, size_t idlen, EC_KEY* remote_pubkey, const char* rid, size_t ridlen, int is_initiator, int do_checksum)
{
    int ret = 0;
    int w;
    size_t len;

    if (!ctx || !ec_key || !remote_pubkey) {
        return 0;
    }

    memset(ctx, 0, sizeof(*ctx));
    
    ctx->id_dgstlen = sizeof(ctx->id_dgst);
    ctx->remote_id_dgstlen = sizeof(ctx->remote_id_dgst);

    ctx->id_dgst_md = EVP_sm3();
    ctx->kdf_md = EVP_sm3();
    ctx->checksum_md = EVP_sm3();
    ctx->point_form = SM2_DEFAULT_POINT_CONVERSION_FORM;

    ctx->is_initiator = is_initiator;
    ctx->do_checksum = do_checksum;

    if (EC_GROUP_cmp(EC_KEY_get0_group(ec_key),
        EC_KEY_get0_group(remote_pubkey), NULL) != 0) {
        goto end;
    }

    len = ctx->id_dgstlen;
    if (!SM2_compute_id_digest(ctx->id_dgst_md, id, idlen,
        ctx->id_dgst, &len, ec_key)) {
        goto end;
    }
    ctx->id_dgstlen = len;

    if (!(ctx->ec_key = EC_KEY_dup(ec_key))) {
        goto end;
    }

    len = ctx->remote_id_dgstlen;
    if (!SM2_compute_id_digest(ctx->id_dgst_md, rid, ridlen,
        ctx->remote_id_dgst, &len, remote_pubkey)) {
        goto end;
    }
    ctx->remote_id_dgstlen = len;

    if (!(ctx->remote_pubkey = EC_KEY_dup(remote_pubkey))) {
        goto end;
    }

    ctx->group = EC_KEY_get0_group(ec_key);
    ctx->bn_ctx = BN_CTX_new();
    ctx->order = BN_new();
    ctx->two_pow_w = BN_new();
    ctx->t = BN_new();

    if (!ctx->bn_ctx || !ctx->order || !ctx->two_pow_w || !ctx->t) {
        goto end;
    }

    if (!EC_GROUP_get_order(ctx->group, ctx->order, ctx->bn_ctx)) {
        goto end;
    }

    w = (BN_num_bits(ctx->order) + 1) / 2 - 1;

    if (!BN_one(ctx->two_pow_w)) {
        goto end;
    }

    if (!BN_lshift(ctx->two_pow_w, ctx->two_pow_w, w)) {
        goto end;
    }

    if (!(ctx->point = EC_POINT_new(ctx->group))) {
        goto end;
    }

    ret = 1;

end:
    if (!ret) SM2_KAP_CTX_cleanup(ctx);
    return ret;
}

int SM2_KAP_prepare(SM2_KAP_CTX* ctx, unsigned char* ephem_point, size_t* ephem_point_len)
{
    int ret = 0;
    const BIGNUM* prikey;
    BIGNUM* h = NULL;
    BIGNUM* r = NULL;
    BIGNUM* x = NULL;

    if (!(prikey = EC_KEY_get0_private_key(ctx->ec_key))) {
        return 0;
    }

    h = BN_new();
    r = BN_new();
    x = BN_new();

    if (!h || !r || !x) {
        goto end;
    }

    do {
        if (!BN_rand_range(r, ctx->order)) {
            goto end;
        }

    } while (BN_is_zero(r));

    if (!EC_POINT_mul(ctx->group, ctx->point, r, NULL, NULL, ctx->bn_ctx)) {
        goto end;
    }

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(ctx->group)) == NID_X9_62_prime_field) {
        if (!EC_POINT_get_affine_coordinates_GFp(ctx->group, ctx->point, x, NULL, ctx->bn_ctx)) {
            goto end;
        }
    }
    else {
        if (!EC_POINT_get_affine_coordinates_GF2m(ctx->group, ctx->point, x, NULL, ctx->bn_ctx)) {
            goto end;
        }
    }

    if (!ctx->t) {
        goto end;
    }

    if (!BN_nnmod(x, x, ctx->two_pow_w, ctx->bn_ctx)) {
        goto end;
    }

    if (!BN_add(x, x, ctx->two_pow_w)) {
        goto end;
    }

    if (!BN_mod_mul(ctx->t, x, r, ctx->order, ctx->bn_ctx)) {
        goto end;
    }

    if (!BN_mod_add(ctx->t, ctx->t, prikey, ctx->order, ctx->bn_ctx)) {
        goto end;
    }

    if (!EC_GROUP_get_cofactor(ctx->group, h, ctx->bn_ctx)) {
        goto end;
    }

    if (!BN_mod_mul(ctx->t, ctx->t, h, ctx->order, ctx->bn_ctx)) {
        goto end;
    }

    ret = EC_POINT_point2oct(ctx->group, ctx->point, ctx->point_form, ephem_point, *ephem_point_len, ctx->bn_ctx);

    if (ret == 0) {
        goto end;
    }

    memcpy(ctx->pt_buf, ephem_point, ret);
    *ephem_point_len = ret;

    ret = 1;

end:
    if (h) BN_free(h);
    if (r) BN_free(r);
    if (x) BN_free(x);

    return ret;
}

int SM2_KAP_compute_key(SM2_KAP_CTX* ctx, const unsigned char* remote_point,size_t remote_point_len, unsigned char* key, size_t keylen, unsigned char* checksum, size_t* checksumlen)
{
    int ret = 0;

    EVP_KDF_CTX* kctx = NULL;
    EVP_MD_CTX* md_ctx = NULL;
    BIGNUM* x = NULL;
    unsigned char share_pt_buf[1 + (OPENSSL_ECC_MAX_FIELD_BITS + 7) / 4 + EVP_MAX_MD_SIZE * 2 + 100];
    unsigned char remote_pt_buf[1 + (OPENSSL_ECC_MAX_FIELD_BITS + 7) / 4 + 111];
    unsigned char dgst[EVP_MAX_MD_SIZE];
    unsigned int dgstlen;
    unsigned int len, bnlen;
    size_t klen = keylen;

    md_ctx = EVP_MD_CTX_new();
    x = BN_new();
    if (!md_ctx || !x) {
        goto end;
    }

    if (!EC_POINT_oct2point(ctx->group, ctx->point, remote_point, remote_point_len, ctx->bn_ctx)) {
        goto end;
    }

    if (!(len = EC_POINT_point2oct(ctx->group, ctx->point, POINT_CONVERSION_UNCOMPRESSED,
        remote_pt_buf, sizeof(remote_pt_buf), ctx->bn_ctx))) {
        goto end;
    }

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(ctx->group)) == NID_X9_62_prime_field) {
        if (!EC_POINT_get_affine_coordinates_GFp(ctx->group, ctx->point, x, NULL, ctx->bn_ctx)) {
            goto end;
        }
    }
    else {
        if (!EC_POINT_get_affine_coordinates_GF2m(ctx->group, ctx->point, x, NULL, ctx->bn_ctx)) {
            goto end;
        }
    }

    if (!BN_nnmod(x, x, ctx->two_pow_w, ctx->bn_ctx)) {
        goto end;
    }
    if (!BN_add(x, x, ctx->two_pow_w)) {
        goto end;
    }

    if (!EC_POINT_mul(ctx->group, ctx->point, NULL, ctx->point, x, ctx->bn_ctx)) {
        goto end;
    }

    if (!EC_POINT_add(ctx->group, ctx->point, ctx->point, EC_KEY_get0_public_key(ctx->remote_pubkey), ctx->bn_ctx)) {
        goto end;
    }

    if (!EC_POINT_mul(ctx->group, ctx->point, NULL, ctx->point, ctx->t, ctx->bn_ctx)) {
        goto end;
    }

    if (EC_POINT_is_at_infinity(ctx->group, ctx->point)) {
        goto end;
    }

    if (!(len = EC_POINT_point2oct(ctx->group, ctx->point, POINT_CONVERSION_UNCOMPRESSED,
        share_pt_buf, sizeof(share_pt_buf), ctx->bn_ctx))) {
        goto end;
    }

    if (ctx->is_initiator) {
        memcpy(share_pt_buf + len, ctx->id_dgst, ctx->id_dgstlen);
        len += ctx->id_dgstlen;
        memcpy(share_pt_buf + len, ctx->remote_id_dgst, ctx->remote_id_dgstlen);
        len += ctx->remote_id_dgstlen;
    }
    else {
        memcpy(share_pt_buf + len, ctx->remote_id_dgst, ctx->remote_id_dgstlen);
        len += ctx->remote_id_dgstlen;
        memcpy(share_pt_buf + len, ctx->id_dgst, ctx->id_dgstlen);
        len += ctx->id_dgstlen;
    }

    const unsigned char* salt = (unsigned char*)"salt_value";
    size_t salt_len = strlen((char*)salt);
    const unsigned char* info = (unsigned char*)"application_specific_info";
    size_t info_len = strlen((char*)info);

    unsigned char out_key[64];
    size_t out_key_len = sizeof(out_key);

    kctx = EVP_KDF_CTX_new_id(EVP_KDF_HKDF);
    
    if (kctx == NULL) {
        goto end;
    }

    if (!EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, ctx->kdf_md)) {
        goto end;
    }

    if (!EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, salt, salt_len)) {
        goto end;
    }

    if (!EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, share_pt_buf + 1, len - 1)) {
        goto end;
    }

    if (!EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_ADD_HKDF_INFO, info, info_len)) {
        goto end;
    }

    if (!EVP_KDF_derive(kctx, key, klen)) {
        goto end;
    }

    if (ctx->do_checksum) {
        if (!EVP_DigestInit_ex(md_ctx, ctx->checksum_md, NULL)) {
            goto end;
        }

        bnlen = BN_num_bytes(ctx->order);

        if (!EVP_DigestUpdate(md_ctx, share_pt_buf + 1, bnlen)) {
            goto end;
        }

        if (ctx->is_initiator) {
            if (!EVP_DigestUpdate(md_ctx, ctx->id_dgst, ctx->id_dgstlen)) {
                goto end;
            }
            if (!EVP_DigestUpdate(md_ctx, ctx->remote_id_dgst, ctx->remote_id_dgstlen)) {
                goto end;
            }
            if (!EVP_DigestUpdate(md_ctx, ctx->pt_buf + 1, bnlen * 2)) {
                goto end;
            }
            if (!EVP_DigestUpdate(md_ctx, remote_pt_buf + 1, bnlen * 2)) {
                goto end;
            }

        }
        else {
            if (!EVP_DigestUpdate(md_ctx, ctx->remote_id_dgst, ctx->remote_id_dgstlen)) {
                goto end;
            }
            if (!EVP_DigestUpdate(md_ctx, ctx->id_dgst, ctx->id_dgstlen)) {
                goto end;
            }
            if (!EVP_DigestUpdate(md_ctx, remote_pt_buf + 1, bnlen * 2)) {
                goto end;
            }
            if (!EVP_DigestUpdate(md_ctx, ctx->pt_buf + 1, bnlen * 2)) {
                goto end;
            }
        }

        if (!EVP_DigestFinal_ex(md_ctx, dgst, &dgstlen)) {
            goto end;
        }

        if (!EVP_DigestInit_ex(md_ctx, ctx->checksum_md, NULL)) {
            goto end;
        }

        if (!EVP_DigestUpdate(md_ctx, "\x02", 1)) {
            goto end;
        }

        if (!EVP_DigestUpdate(md_ctx, share_pt_buf + 1 + bnlen, bnlen)) {
            goto end;
        }

        if (!EVP_DigestUpdate(md_ctx, dgst, dgstlen)) {
            goto end;
        }

        if (ctx->is_initiator) {
            if (!EVP_DigestFinal_ex(md_ctx, ctx->checksum, &len)) {
                goto end;
            }

        }
        else {
            if (!EVP_DigestFinal_ex(md_ctx, checksum, &len)) {
                goto end;
            }
            *checksumlen = len;
        }

        if (!EVP_DigestInit_ex(md_ctx, ctx->checksum_md, NULL)) {
            goto end;
        }

        if (!EVP_DigestUpdate(md_ctx, "\x03", 1)) {
            goto end;
        }

        if (!EVP_DigestUpdate(md_ctx, share_pt_buf + 1 + bnlen, bnlen)) {
            goto end;
        }

        if (!EVP_DigestUpdate(md_ctx, dgst, dgstlen)) {
            goto end;
        }

        if (ctx->is_initiator) {
            if (!EVP_DigestFinal_ex(md_ctx, checksum, &len)) {
                goto end;
            }
            *checksumlen = len;

        }
        else {
            if (!EVP_DigestFinal_ex(md_ctx, ctx->checksum, &len)) {
                goto end;
            }
        }

    }

    ret = 1;

end:
    EVP_KDF_CTX_free(kctx);
    EVP_MD_CTX_free(md_ctx);
    BN_free(x);
    return ret;
}

int SM2_KAP_final_check(SM2_KAP_CTX* ctx, const unsigned char* checksum,size_t checksumlen)
{
    if (ctx->do_checksum) {
        if (checksumlen != (size_t)EVP_MD_size(ctx->checksum_md)) {
            return 0;
        }
        if (memcmp(ctx->checksum, checksum, checksumlen)) {
            return 0;
        }
    }

    return 1;
}

