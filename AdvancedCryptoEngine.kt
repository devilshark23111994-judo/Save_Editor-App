package com.example.savefileeditor

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import java.io.File

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            AdvancedSaveEditorScreen()
        }
    }
}

@Composable
fun AdvancedSaveEditorScreen() {
    var secretKey by remember { mutableStateOf("1234567890123456") }
    var ivKey by remember { mutableStateOf("1234567890123456") }
    var rawInputBytes by remember { mutableStateOf(ByteArray(0)) }
    var cleanDecryptedText by remember { mutableStateOf("") }
    var analysisResult by remember { mutableStateOf<FileAnalysisResult?>(null) }
    var statusLog by remember { mutableStateOf("Engine Ready. Upload or paste raw file bytes.") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState())
    ) {
        Text("Advanced Save File Decryptor & Inspector", style = MaterialTheme.typography.headlineSmall)
        Spacer(modifier = Modifier.height(12.dp))

        // Keys Input Section
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = secretKey,
                onValueChange = { secretKey = it },
                label = { Text("AES Secret Key") },
                modifier = Modifier.weight(1f)
            )
            OutlinedTextField(
                value = ivKey,
                onValueChange = { ivKey = it },
                label = { Text("AES IV Key") },
                modifier = Modifier.weight(1f)
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Action Buttons
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    if (rawInputBytes.isNotEmpty()) {
                        val decrypted = AdvancedCryptoEngine.decryptAES(rawInputBytes, secretKey, ivKey)
                        cleanDecryptedText = AdvancedCryptoEngine.sanitizeToReadableEnglish(decrypted)
                        statusLog = "Decrypted & Sanitized successfully (Garbage characters stripped)."
                    } else {
                        statusLog = "Error: No file bytes loaded."
                    }
                },
                modifier = Modifier.weight(1f)
            ) {
                Text("Decrypt & Clean")
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // File Structural Inspector Panel
        analysisResult?.let { info ->
            Card(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("File Metadata Analysis", style = MaterialTheme.typography.titleMedium)
                    Divider(modifier = Modifier.padding(vertical = 4.dp))
                    Text("Internal Format: ${info.detectedFormat}")
                    Text("Magic Header: ${info.hexHeader}")
                    Text("Encrypted State: ${if (info.isLikelyEncrypted) "High Entropy (Encrypted/Compressed)" else "Plain Binary/Text"}")
                    Text("MD5 Hash: ${info.md5Hash}")
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Output Display Area
        Text("Decrypted Output (English Sanitized):", style = MaterialTheme.typography.titleSmall)
        OutlinedTextField(
            value = cleanDecryptedText,
            onValueChange = { cleanDecryptedText = it },
            modifier = Modifier
                .fillMaxWidth()
                .height(250.dp),
            placeholder = { Text("Decrypted plain text or structural data will appear here...") }
        )

        Spacer(modifier = Modifier.height(8.dp))
        Text("System Log: $statusLog", style = MaterialTheme.typography.bodySmall)
    }
}

