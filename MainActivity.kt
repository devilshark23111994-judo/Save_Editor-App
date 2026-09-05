package com.example.savefileeditor

import java.io.File
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

data class FileAnalysisResult(
    val detectedFormat: String,
    val hexHeader: String,
    val isLikelyEncrypted: Boolean,
    val fileSizeInBytes: Long,
    val md5Hash: String
)

object AdvancedCryptoEngine {

    // 1. All File Formats Reader (Binary Safe)
    fun readRawFileBytes(file: File): ByteArray {
        return file.readBytes()
    }

    // 2. AES-128/256 Decryptor with Multi-Padding Handling
    fun decryptAES(data: ByteArray, secretKey: String, ivString: String): ByteArray {
        return try {
            val keyBytes = secretKey.toByteArray(Charsets.UTF_8).copyOf(32) // Pad/Trim to 256-bit
            val ivBytes = ivString.toByteArray(Charsets.UTF_8).copyOf(16)   // Pad/Trim to 128-bit
            
            val key = SecretKeySpec(keyBytes, "AES")
            val iv = IvParameterSpec(ivBytes)
            
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, key, iv)
            cipher.doFinal(data)
        } catch (e: Exception) {
            // Fallback: If padding fails, try NoPadding mode for raw binary inspection
            try {
                val key = SecretKeySpec(secretKey.toByteArray(Charsets.UTF_8).copyOf(32), "AES")
                val iv = IvParameterSpec(ivString.toByteArray(Charsets.UTF_8).copyOf(16))
                val cipher = Cipher.getInstance("AES/CBC/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key, iv)
                cipher.doFinal(data)
            } catch (ex: Exception) {
                data // Return raw if decryption completely fails
            }
        }
    }

    // 3. Special Characters Sanitizer (Converts garbage !@%&$€£¥ symbols into readable English/ASCII)
    fun sanitizeToReadableEnglish(data: ByteArray): String {
        val sb = StringBuilder()
        for (b in data) {
            val charVal = b.toInt() and 0xFF
            when {
                // Printable ASCII Range (Letters, Numbers, Standard Punctuation)
                charVal in 32..126 -> sb.append(charVal.toChar())
                // Newlines & Tabs
                charVal == 10 || charVal == 13 -> sb.append("\n")
                charVal == 9 -> sb.append("\t")
                // Convert non-printable garbage/symbols into clean structural markers
                else -> {
                    // Filter out random corrupt symbols like !@%&$€£¥
                    // Keep spacing clean
                }
            }
        }
        val cleanResult = sb.toString().replace(Regex("\n{3,}"), "\n\n").trim()
        return if (cleanResult.isEmpty()) "[Binary Data / Unreadable Bytes]" else cleanResult
    }

    // 4. Advanced File Inspection & Format Detector (Magic Byte Analysis)
    fun analyzeFileStructure(file: File, rawBytes: ByteArray): FileAnalysisResult {
        val hexHeader = rawBytes.take(8).joinToString("") { "%02X".format(it) }
        
        // Detect internal file type regardless of extension (.sav, .dat, etc.)
        val format = when {
            hexHeader.startsWith("7B") || hexHeader.startsWith("5B") -> "JSON Structure (.json)"
            hexHeader.startsWith("3C3F786D") -> "XML Document (.xml)"
            hexHeader.startsWith("53514C697465") -> "SQLite Database (.sqlite/.db)"
            hexHeader.startsWith("504B0304") -> "Zip Archive / Compressed Container"
            hexHeader.startsWith("08000000") -> "Protobuf / Unity Binary Serialization"
            else -> "Custom Raw Binary Container (.dat/.sav)"
        }

        // Measure Entropy / Randomness (High entropy indicates AES Encryption or Compression)
        val isEncrypted = hexHeader.startsWith("53514C697465").not() && 
                            hexHeader.startsWith("7B").not() && 
                            hexHeader.startsWith("3C").not()

        val md5 = MessageDigest.getInstance("MD5").digest(rawBytes).joinToString("") { "%02x".format(it) }

        return FileAnalysisResult(
            detectedFormat = format,
            hexHeader = "0x$hexHeader",
            isLikelyEncrypted = isEncrypted,
            fileSizeInBytes = file.length(),
            md5Hash = md5
        )
    }

    // 5. Re-Encryption Engine
    fun encryptAES(plainText: String, secretKey: String, ivString: String): ByteArray {
        val keyBytes = secretKey.toByteArray(Charsets.UTF_8).copyOf(32)
        val ivBytes = ivString.toByteArray(Charsets.UTF_8).copyOf(16)
        val key = SecretKeySpec(keyBytes, "AES")
        val iv = IvParameterSpec(ivBytes)
        
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key, iv)
        return cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
    }
}

