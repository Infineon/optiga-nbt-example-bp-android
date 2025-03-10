// SPDX-FileCopyrightText: Copyright (c) 2024-2025 Infineon Technologies AG
// SPDX-License-Identifier: MIT

package com.infineon.css.nbt_brandprotection_demonstrator.usecase_brandprotection;

import android.nfc.NdefMessage;
import android.os.Parcelable;

import androidx.annotation.NonNull;

import com.infineon.css.nbt_brandprotection_demonstrator.MainActivity;
import com.infineon.css.nbt_brandprotection_demonstrator.usecase_brandprotection.ndef_handler.*;
import com.infineon.hsw.apdu.ApduChannel;
import com.infineon.hsw.apdu.ApduException;
import com.infineon.hsw.apdu.nbt.NbtApduResponse;
import com.infineon.hsw.apdu.nbt.NbtCommandSet;
import com.infineon.hsw.ndef.exceptions.NdefException;
import com.infineon.hsw.utils.UtilException;

import java.io.ByteArrayInputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Random;

/**
 * The BrandProtectionUsecase Class represents the brand protection usecase with a NBT sample.
 * It needs to be provided with a ApduChannel and the raw Ndef Message of the NBT sample to run the
 * use case. According to the use case the class will:
 * - Parse the certificate from the tags ndef message
 * - Verify the certificate
 * - Send an authenticate command with a random challenge
 * - Read and parse the root certificates public key from a file
 * - Verify the received signature
 */

public class BrandProtectionUsecase {

    /**
     * Usecase specific NDEF handler providing access to ndef coding and decoding functionality
     */
    private final INdefHandler handler;

    /**
     * Algorithm identifier for SHA256 ECDSA signature.
     */
    private static final String ALGORITHM_SHA256_ECDSA = "SHA256withECDSA";

    /**
     * Random challenge needed for authenticate cmd
     */
    private final byte[] challenge = new byte[8];

    /**
     * Holds signature from sample
     */
    private byte[] signature;

    /**
     * Instance of the APDU command set
     */
    private final NbtCommandSet commandSet;

    /**
     * Instance of the APDU response
     */
    private NbtApduResponse apduResponse;


    /**
     * Constructor validates parameters and holds them for members
     *
     * @param apduChannel APDU specific channel
     * @throws UtilException Thrown by libraries utils
     * @throws ApduException Thrown by command set of APDU library
     */
    public BrandProtectionUsecase(@NonNull ApduChannel apduChannel)
            throws UtilException, ApduException {

        //Infineon or Android handler can be selected
        this.handler = new InfineonHandler();
        this.commandSet = new NbtCommandSet(apduChannel, 0);
        this.apduResponse = null;

        //Generate random challenge for signature computation
        new Random().nextBytes(challenge);
    }

    /**
     * Will execute the use case accordingly:
     * - Parse the certificate from the tags ndef message
     * - Verify the certificate
     * - Send an authenticate command with a random challenge
     * - Read and parse the root certificates public key from a file
     * - Verify the received signature
     *
     * @param rawNdefMessage The raw NDEF message read by the host device
     * @throws SignatureException Thrown if signature could not be verified
     * @throws InvalidKeyException Thrown if public key could not be extracted from the certificate
     * @throws ApduException Thrown by command set of APDU library
     * @throws CertificateException Thrown if certificate could not be verified
     * @throws NoSuchAlgorithmException Thrown if certificate could not be verified
     * @throws NoSuchProviderException Thrown if certificate could not be verified
     * @throws NdefException An exception in the NDEF file specific library occurred
     */
    public void execute(@NonNull Parcelable[] rawNdefMessage)
            throws SignatureException, InvalidKeyException, ApduException, CertificateException,
            NoSuchAlgorithmException, NoSuchProviderException, NdefException {

        //Extract certificate from ndef message and initialize nfc channel
        X509Certificate cert = this.handler.parseCertFromNdef(((NdefMessage) rawNdefMessage[0]).toByteArray());

        verifyCertificate(cert);
        authenticate();
        verifySignature(cert.getPublicKey(), this.challenge, this.signature);

    }

    /**
     * Sends the AUTHENTICATE_TAG cmd with a random challenge to receive a signature to verify
     *
     * @throws ApduException Thrown by command set of APDU library
     */
    private void authenticate() throws ApduException {

        this.apduResponse = this.commandSet.selectApplication();
        this.apduResponse.checkOK();
        this.apduResponse = this.commandSet.authenticateTag(this.challenge);
        this.apduResponse.checkOK();
        this.signature = this.apduResponse.getData();
    }

    /**
     * Verifies a the root certificate with its public key and checks if it is expired
     *
     * @param cert CA certificate
     * @throws CertificateException Thrown if certificate could not be verified
     * @throws NoSuchAlgorithmException Thrown if Android OS does not support required crypto operation
     * @throws NoSuchProviderException Thrown if certificate could not be verified
     */
    private void verifyCertificate(@NonNull X509Certificate cert)
            throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {

            //Check date and verify certificate with public key
            cert.checkValidity(new Date());
            for (PublicKey publicKey : getCaPublicKeys()) {
                try {
                    cert.verify(publicKey);
                    return;
                } catch(CertificateException|InvalidKeyException|SignatureException e) {
                    // Ignore and try next one
                }
            }
            throw new CertificateException();
    }

    /**
     * Verifies given ECDSA signature
     *
     * @param publicKey Public key to be used for ECDSA signature verification
     * @param challenge  Challenge to verify signature for
     * @param signature Signature data to be verified
     * @throws SignatureException Thrown if signature could not be verified
     * @throws InvalidKeyException Thrown if public key could not be extracted from the certificate
     * @throws NoSuchAlgorithmException Thrown if Android OS does not support required crypto operation
     */
    private void verifySignature(@NonNull final PublicKey publicKey, @NonNull final byte[] challenge, @NonNull final byte[] signature)
            throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {

        Signature verifier;

        verifier = Signature.getInstance(ALGORITHM_SHA256_ECDSA);
        verifier.initVerify(publicKey);
        verifier.update(challenge);

        if(!verifier.verify(signature)){
            throw new SignatureException();
        }
    }

    /**
     * Returns all root CA public keys used by {@link #verifyCertificate(X509Certificate)} to check
     * NBT's certificate.
     *
     * @return All root CA public keys for certificate verification
     * @throws CertificateException Thrown if certificate string syntactically invalid
     */
    private PublicKey[] getCaPublicKeys() throws CertificateException {
        return new PublicKey[] {
                readPublicKey(MainActivity.manufacturing_ca_cert),
                readPublicKey(MainActivity.usecase_ca_cert)
        };
    }

    /**
     * Parses the public key from the given certificate string
     *
     * @return Return public key which was extracted from the certificate
     * @throws CertificateException Thrown if certificate string syntactically invalid
     */
    private PublicKey readPublicKey(String certificateString) throws CertificateException {

        String certificatePEM = certificateString
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replaceAll("\r", "")
                .replace("-----END CERTIFICATE-----", "");

        byte[] decoded = Base64.getDecoder().decode(certificatePEM);
        ByteArrayInputStream is = new ByteArrayInputStream(decoded);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(is);

        return cert.getPublicKey();
    }
}
