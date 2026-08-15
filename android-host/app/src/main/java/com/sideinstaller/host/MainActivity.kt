package com.sideinstaller.host

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.io.File

class MainActivity : ComponentActivity() {

    private lateinit var hostManager: PairingHostManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        hostManager = PairingHostManager(this)

        setContent {
            var statusText by remember { mutableStateOf("Ready to start RemotePairing host.") }
            var pairingPin by remember { mutableStateOf<String?>(null) }
            var isRunning by remember { mutableStateOf(false) }
            var downloadUrl by remember { mutableStateOf<String?>(null) }

            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = "SideInstaller Host",
                            style = MaterialTheme.typography.headlineLarge,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        Text(
                            text = "iOS RemotePairing Host for Android",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        Spacer(modifier = Modifier.height(32.dp))

                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant
                            )
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text(
                                    text = "Status:",
                                    style = MaterialTheme.typography.labelLarge,
                                    color = MaterialTheme.colorScheme.primary
                                )
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = statusText,
                                    style = MaterialTheme.typography.bodyLarge
                                )
                            }
                        }

                        pairingPin?.let { pin ->
                            Spacer(modifier = Modifier.height(24.dp))
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(
                                    containerColor = MaterialTheme.colorScheme.primaryContainer
                                )
                            ) {
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(20.dp),
                                    horizontalAlignment = Alignment.CenterHorizontally
                                ) {
                                    Text(
                                        text = "Enter PIN on iPhone:",
                                        style = MaterialTheme.typography.labelMedium
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text(
                                        text = pin,
                                        fontSize = 36.sp,
                                        fontWeight = FontWeight.Bold,
                                        letterSpacing = 4.sp
                                    )
                                }
                            }
                        }

                        downloadUrl?.let { url ->
                            Spacer(modifier = Modifier.height(24.dp))
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(
                                    containerColor = MaterialTheme.colorScheme.secondaryContainer
                                )
                            ) {
                                Column(
                                    modifier = Modifier.padding(16.dp),
                                    horizontalAlignment = Alignment.CenterHorizontally
                                ) {
                                    Text(text = "Pairing Complete! Download file at:")
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = url,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.onSecondaryContainer
                                    )
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(32.dp))

                        Button(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(50.dp),
                            enabled = !isRunning,
                            onClick = {
                                isRunning = true
                                statusText = "Broadcasting Bonjour host over Hotspot/Wi-Fi..."
                                pairingPin = "......"

                                hostManager.startPairingHost(
                                    onPinGenerated = { generatedPin ->
                                        pairingPin = generatedPin
                                        statusText = "Waiting for iPhone in Settings > Developer Mode..."
                                    },
                                    onSuccess = { pairingFile ->
                                        isRunning = false
                                        statusText = "Pairing successful!"

                                        val ip = hostManager.getDeviceIpAddress()
                                        val port = 8080
                                        hostManager.startFileServer(pairingFile, port)
                                        downloadUrl = "http://$ip:$port/pairing.pair"
                                    },
                                    onError = { error ->
                                        isRunning = false
                                        pairingPin = null
                                        statusText = "Error: $error"
                                    }
                                )
                            }
                        ) {
                            Text(if (isRunning) "Pairing in Progress..." else "Start Pairing Host")
                        }
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        hostManager.stopAdvertising()
        hostManager.stopFileServer()
    }
}
