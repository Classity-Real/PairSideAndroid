package com.sideinstaller.host

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.io.File
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.ServerSocket
import java.security.SecureRandom

class PairingHostManager(private val context: Context) {

    companion object {
        private const val TAG = "PairingHostManager"
    }

    private var nsdManager: NsdManager? = null
    private var registrationListener: NsdManager.RegistrationListener? = null
    private var serverSocket: ServerSocket? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    private val hostIdentifier: String = java.util.UUID.randomUUID().toString().uppercase()

    fun startPairingHost(
        onPinGenerated: (String) -> Unit,
        onSuccess: (File) -> Unit,
        onError: (String) -> Unit
    ) {
        Thread {
            try {
                val listener = ServerSocket(0) // pick a free port
                val port = listener.localPort
                serverSocket = listener
                registerBonjourService(port)
                Log.d(TAG, "Advertising pairable host on port $port, waiting for a device...")

                val clientSocket = listener.accept() // blocks until iPhone connects
                Log.d(TAG, "Device connected from ${clientSocket.inetAddress}")

                val host = PairableHost(clientSocket, hostIdentifier, "SideInstaller Host")

                val srpResult = host.acceptHandshakeAndSrp { pin ->
                    mainHandler.post { onPinGenerated(pin) }
                }
                Log.d(TAG, "SRP pair-setup phase complete (M1-M4). Session key established.")

                val hostAltIrk = ByteArray(16).also { SecureRandom().nextBytes(it) }
                val ed25519 = Ed25519KeyPair.generate()
                val peerDevice = host.completeIdentityExchange(srpResult, hostAltIrk, ed25519)

                Log.i(TAG, "Pairing complete! Paired with ${peerDevice.name} (${peerDevice.model})")
                mainHandler.post {
                    onSuccess(File(context.filesDir, "pairing.pair")) // placeholder file for now
                }
                host.close()

            } catch (e: Exception) {
                Log.e(TAG, "Pairing host error", e)
                mainHandler.post { onError(e.localizedMessage ?: "Unknown error") }
            } finally {
                stopAdvertising()
            }
        }.start()
    }

    private fun registerBonjourService(port: Int) {
        val serviceInfo = NsdServiceInfo().apply {
            serviceName = "SideInstallerHost"
            serviceType = "_remotepairing-pairable-host._tcp."
            setPort(port)
            setAttribute("name", "SideInstaller Host")
            setAttribute("identifier", hostIdentifier)
            setAttribute("model", "Mac17,7")
            setAttribute("flags", "1")
            setAttribute("ver", "26")
            setAttribute("minVer", "17")
        }

        nsdManager = (context.getSystemService(Context.NSD_SERVICE) as NsdManager)
        registrationListener = object : NsdManager.RegistrationListener {
            override fun onServiceRegistered(serviceInfo: NsdServiceInfo) {
                Log.d(TAG, "Bonjour service registered successfully.")
            }
            override fun onRegistrationFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                Log.e(TAG, "Bonjour registration failed: $errorCode")
            }
            override fun onServiceUnregistered(serviceInfo: NsdServiceInfo) {}
            override fun onUnregistrationFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
        }

        nsdManager?.registerService(serviceInfo, NsdManager.PROTOCOL_DNS_SD, registrationListener)
    }

    fun stopAdvertising() {
        registrationListener?.let {
            try {
                nsdManager?.unregisterService(it)
            } catch (e: Exception) {
                Log.e(TAG, "Error unregistering NSD service", e)
            }
        }
        try {
            serverSocket?.close()
        } catch (_: Exception) {}
        serverSocket = null
    }

    fun startFileServer(file: File, port: Int) {
        // Not needed yet - pairing record delivery approach TBD.
    }

    fun stopFileServer() {}

    fun getDeviceIpAddress(): String {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces().toList()
            for (intf in interfaces) {
                if (intf.isUp && !intf.isLoopback) {
                    for (addr in intf.inetAddresses) {
                        if (!addr.isLoopbackAddress && addr is Inet4Address) {
                            val ip = addr.hostAddress ?: continue
                            if (ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.")) {
                                return ip
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting IP address", e)
        }
        return "127.0.0.1"
    }
}
