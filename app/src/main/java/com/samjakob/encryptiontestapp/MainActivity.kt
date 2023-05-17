package com.samjakob.encryptiontestapp

import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.AuthenticationCallback
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonColors
import androidx.compose.material3.ButtonDefaults.buttonColors
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.Dp
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import com.samjakob.encryptiontestapp.ui.theme.EncryptionTestAppTheme
import java.security.KeyStore

class MainActivity : FragmentActivity() {

    private lateinit var keyStore: KeyStore;

    class AppAuthCallback(): AuthenticationCallback() {
        private lateinit var onSuccess: (result: BiometricPrompt.AuthenticationResult) -> Unit;

        constructor(onSuccess: (result: BiometricPrompt.AuthenticationResult) -> Unit) : this() {
            this.onSuccess = onSuccess
        }

        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(result)
            onSuccess(result)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        setContent {
            EncryptionTestAppTheme {
                // A surface container using the 'background' color from the theme
                HomeScreen()
            }
        }
    }

    @Composable
    fun HomeScreen() {
        val fragment: MainActivity = this

        val encryptedText = rememberSaveable(stateSaver = TextFieldValue.Saver) {
            mutableStateOf(TextFieldValue())
        }

        Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Column {
                LoadStoreButtons( onLoad = {
                    val prefs = applicationContext.getSharedPreferences("PLATFORM", MODE_PRIVATE)
                    if (prefs.contains("encryptedData")) {
                        val encryptedData = prefs.getString("encryptedData", null)
                        encryptedData?.let { encryptedText.value = TextFieldValue(it) }
                    }
                    Toast
                        .makeText(applicationContext, "Loaded", Toast.LENGTH_SHORT)
                        .show()
                }, onStore = {
                    val prefs = applicationContext.getSharedPreferences("PLATFORM", MODE_PRIVATE)
                    val editor = prefs.edit()
                    editor.putString("encryptedData", encryptedText.value.text)
                    if (editor.commit()) {
                        Toast
                            .makeText(applicationContext, "Stored", Toast.LENGTH_SHORT)
                            .show()
                    }
                } )
                PlainTextInput(modifier = Modifier.fillMaxWidth(), onSubmit = {
                    val encryptedData = Encryption.encrypt(keyStore, applicationContext, it.toByteArray())
                    encryptedText.value = TextFieldValue(Base64.encodeToString(encryptedData, Base64.DEFAULT))
                })
                EncryptedTextInput(modifier = Modifier.fillMaxWidth(), text = encryptedText, onSubmit = {
                    val rawValue = encryptedText.value.text
                    val value = Base64.decode(rawValue, Base64.DEFAULT)

                    val info = BiometricPrompt.PromptInfo.Builder()
                        .setTitle("Decrypt Data")
                        .setSubtitle("Decrypt your data")
                        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                        .setNegativeButtonText("Cancel")
                        .build()

                    val cryptoObject = Encryption.createCryptoObject(keyStore)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        BiometricPrompt(fragment, mainExecutor, AppAuthCallback(onSuccess = {
                            it.cryptoObject?.let {
                                cryptoObject ->
                                run {
                                    val decryptedValue = String(Encryption.decrypt(cryptoObject, value))
                                    Toast
                                        .makeText(applicationContext, "Decrypted: $decryptedValue", Toast.LENGTH_SHORT)
                                        .show()
                                }
                            }
                        })).authenticate(info, cryptoObject)
                    }
                })
            }
        }
    }

    @Composable
    fun LoadStoreButtons(onLoad: () -> Unit, onStore: () -> Unit) {
        Row (
            modifier = Modifier.fillMaxWidth(),
        ) {
            Button(onClick = onLoad) {
                Text(text = "Load")
            }
            Spacer(modifier = Modifier.width(Dp(20F)))
            Button(onClick = onStore) {
                Text(text = "Store")
            }
            Spacer(modifier = Modifier.width(Dp(20F)))
            Button(colors = buttonColors(containerColor = MaterialTheme.colorScheme.error), onClick = {
                Encryption.deleteKey(keyStore)
            }) {
                Text("Delete Key")
            }
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun PlainTextInput(onSubmit: (String) -> Unit, modifier: Modifier = Modifier) {
        var text by rememberSaveable(stateSaver = TextFieldValue.Saver) {
            mutableStateOf(TextFieldValue())
        }

        OutlinedTextField(
            modifier = modifier,
            value = text,
            onValueChange = { text = it },
            label = { Text("Plain Text") }
        )

        Button(onClick = { onSubmit(text.text) }) {
            Text("Encrypt")
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun EncryptedTextInput(text: MutableState<TextFieldValue>, onSubmit: (String) -> Unit, modifier: Modifier = Modifier) {
        OutlinedTextField(
            modifier = modifier,
            value = text.value,
            onValueChange = { text.value = it },
            label = { Text("Cipher Text") }
        )

        Button(onClick = { onSubmit(text.value.text) }) {
            Text("Decrypt")
        }
    }
}
