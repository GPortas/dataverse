package edu.harvard.iq.dataverse.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Base64;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

public class JWTUtil {

    private static final String ALGORITHM_RSA = "RSA";

    // PoC values
    private static final String RSA_PUBLIC_KEY_STR = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCHM3Wht/1OWNXr56QSX6gTOmZGE16gpm6+5bPtB3WfOC5az3FdzAcql0NMcc9opXLSeM/ZfFM1io92bY86fQ3cNgT9oZ0vT52rS0SamAVX2w/5tdjvpY2vIzIqdzrF67Lz6ylV8uXTbtvFiIW05963URkrLYqZPvnYodqigy3OEQIDAQAB";
    private static final String RSA_PRIVATE_KEY_STR = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIczdaG3/U5Y1evnpBJfqBM6ZkYTXqCmbr7ls+0HdZ84LlrPcV3MByqXQ0xxz2ilctJ4z9l8UzWKj3Ztjzp9Ddw2BP2hnS9PnatLRJqYBVfbD/m12O+lja8jMip3OsXrsvPrKVXy5dNu28WIhbTn3rdRGSstipk++dih2qKDLc4RAgMBAAECgYB6U/wt64xcdBJyVO9l1Hj9lMxuwR3QW2Y+gRVP9HzfJ/UBI0qepHkjdyNkKmGQfIoslzTwwgWDny/45l4+fGGptRalAKz9ktse6RtmZT92ezbkzkyQzU1HzTaCmMwFr3nzX8VUQcuaeAOcNevpIymFi6Uvbn7P7n+7EBd5OMymcQJBANxQXjUJuEzZeS8+Am01ct6L/AN7yBhwDG45iDZ2tqKdTATRGyYsmlMBKZd2HFQZo0BoFjawgKRhnoDq5bn6f90CQQCdGcM4rJB2L2GRai68t+9WE0jnA/Wss045jpTUTz3QjYd+5nlt9MdF8CskfebIreD09Xibl8SyYCFvS+wefP3FAkBuFoq8nfrGC/WOMcIsqASaSADKDNRTwcm0WnNCI9fnMgqGbabPUIJc77vEv3QwYg89Y8WV1mSxv0XgzX+1iwLRAkAKw/gvywt/PdH20Arx3bzl7h5hzlCojAUBRrcGMYPv5bLyTELn+Q0qysF6F7KX7+ppfuTL7MOK4bGI2fANSs1tAkEAnYQEOxBBWgvzDMn3hHnlKxZ8vq7bcTmjROBtDp0GCNfhNaQMjJ3YBLiLtWDVK+U9HQgR4SsDF06Eaa6qQ8HOuQ==";
    private static final String JWT_ISSUER = "Dataverse";
    private static final long JWT_EXPIRATION_TIME_MILLIS = 900000;

    static public String createJWTToken(Long userId) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Algorithm algorithm = Algorithm.RSA256(getRSAPublicKey(), getRSAPrivateKey());
        return JWT.create().withIssuer(JWT_ISSUER).withExpiresAt(new Date(System.currentTimeMillis() + JWT_EXPIRATION_TIME_MILLIS)).withSubject(userId.toString()).sign(algorithm);
    }

    public static DecodedJWT verifyJWTToken(String token) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Algorithm algorithm = Algorithm.RSA256(getRSAPublicKey(), getRSAPrivateKey());
        JWTVerifier verifier = JWT.require(algorithm).withIssuer(JWT_ISSUER).build();
        return verifier.verify(token);
    }

    public static RSAPublicKey getRSAPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encoded = Base64.decodeBase64(RSA_PUBLIC_KEY_STR);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    public static RSAPrivateKey getRSAPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encoded = Base64.decodeBase64(RSA_PRIVATE_KEY_STR);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }
}
