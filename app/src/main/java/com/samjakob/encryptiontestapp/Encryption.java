package com.samjakob.encryptiontestapp;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricPrompt;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class Encryption {

    private static final String KEY_NAME = "DEFAULT_KEY";
    private static final String CIPHER_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public static byte[] encrypt(KeyStore keyStore, Context context, byte[] data) {
        try {
            if (!keyStore.containsAlias(KEY_NAME)) {
                generateKeyPair(context);
            }

            return encrypt(keyStore, data);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return data;
    }

    private static void generateKeyPair(Context context) {
        KeyGenParameterSpec.Builder keySpecBuilder = new KeyGenParameterSpec.Builder(
                Encryption.KEY_NAME, KeyProperties.PURPOSE_DECRYPT
        )
                // Require user authentication for usage of the key.
                .setUserAuthenticationRequired(true)
                // Also handled by setUserAuthenticationParameters for Android R+.
                .setUserAuthenticationValidityDurationSeconds(-1)
                // Use OAEP padding for RSA.
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                // Use 2048-bit keys.
                .setKeySize(2048)
                // Use SHA-256 key digest.
                .setDigests(KeyProperties.DIGEST_SHA256)
                ;

        // On supported devices, signal that new biometrics being enrolled should not
        // trigger invalidation of the key (we trust the user's device in the current
        // security model and an existing biometric authentication would be required
        // to enroll a new one).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            keySpecBuilder = keySpecBuilder.setInvalidatedByBiometricEnrollment(false);
        }

        // On supported devices, signal that usage of the key requires the device to
        // be unlocked.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            keySpecBuilder = keySpecBuilder.setUnlockedDeviceRequired(true);
        }

        // On supported devices, more precisely set the requirement put in place by
        // setUserAuthenticationValidityDurationSeconds, that strong biometric security
        // must be used every time the key is used.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            keySpecBuilder = keySpecBuilder.setUserAuthenticationParameters(
                    // Timeout = 0 requires authentication every time the key is used.
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG
            );
        }

        // If there is a StrongBox implementation on the device, and the
        // setIsStrongBoxBacked API is supported by the device call
        // setIsStrongBoxBacked to use it.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            keySpecBuilder = keySpecBuilder.setIsStrongBoxBacked(true);
        }

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA,
                    "AndroidKeyStore"
            );

            // Generate the keypair using AndroidKeyStore and the above requirements.
            keyPairGenerator.initialize(keySpecBuilder.build());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Load the key information to verify that the key meets the necessary
            // standards.
            KeyFactory factory = KeyFactory.getInstance(
                    keyPair.getPrivate().getAlgorithm(), "AndroidKeyStore"
            );
            KeyInfo keyInfo = factory.getKeySpec(keyPair.getPrivate(), KeyInfo.class);

            // Ensure that the key has been generated securely, preventing its use if it
            // hasn't.
            boolean isSecureKey;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                // The key is secure if the key is protected by at least a trusted environment.
                isSecureKey = (keyInfo.getSecurityLevel() >= KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT)
                        // Or, if the exact nature of security is unknown but it is guaranteed to be
                        // SECURITY_LEVEL_TRUSTED_ENVIRONMENT.
                        || keyInfo.getSecurityLevel() == KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE;
            } else {
                // On older systems fallback to checking isInsideSecureHardware.
                // This has been replaced on newer OS builds by getSecurityLevel.
                isSecureKey = keyInfo.isInsideSecureHardware();
            }

            isSecureKey &= keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware();

            if (!isSecureKey) {
                throw new Error("Failed to generate a secure key.");
            }

        } catch (Exception ex) {
            ex.printStackTrace();
            throw new Error(ex);
        }
    }

    public static void deleteKey(KeyStore keyStore) {
        try {
            keyStore.deleteEntry(KEY_NAME);
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new Error(ex);
        }
    }

    private static byte[] encrypt(KeyStore keyStore, byte[] data) {
        try {
            PublicKey publicKey = keyStore.getCertificate(Encryption.KEY_NAME).getPublicKey();
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
            return cipher.doFinal(data);
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new Error();
        }
    }

    public static BiometricPrompt.CryptoObject createCryptoObject(
        @NonNull KeyStore appKeyStore
    ) {
        try {
            PrivateKey privateKey = (PrivateKey) appKeyStore.getKey(KEY_NAME, null);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                return new BiometricPrompt.CryptoObject(cipher);
            } else {
                throw new Error("invalid version, must be at least Android P");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new Error();
        }
    }

    public static byte[] decrypt(@NonNull BiometricPrompt.CryptoObject cryptoObject, byte[] data) {
        try {
            Cipher cipher;
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                cipher = Objects.requireNonNull(cryptoObject.getCipher());
            } else {
                throw new Error("invalid version, must be at least Android P");
            }
            return cipher.doFinal(data);
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new Error();
        }
    }

}
