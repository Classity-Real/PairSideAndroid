package com.sideinstaller.host

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.sun.net.httpserver.HttpServer
import java.io.File
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.NetworkInterface

class PairingHostManager(private val context: Context) {

    companion object {
        private const val TAG = "PairingHostManager"
        init {
            try {
                System.loadLibrary("sideinstaller_ffi")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load native library sideinstaller_ffi", e)
            }
        }
    }

    private var nsdManager: NsdManager? = null
    private var registrationListener: NsdManager.RegistrationListener? = null
    private var httpServer: HttpServer? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    private external fun nativeRunHost(bindIp: String, hostName: String, outputPath: String): Int

    fun startPairingHost(
        onPinGenerated: (String) -> Unit,
        onSuccess: (File) -> Unit,
        onError: (String) -> Unit
    ) {
        val outputFile = File(context.filesDir, "pairing.pair")
        if (outputFile.exists()) {
            outputFile.delete()
        }

        val servicePort = 52345
        registerBonjourService(servicePort)

        mainHandler.post { onPinGenerated("123456") }

        Thread {
            try {
                Log.d(TAG, "Starting native run host on 0.0.0.0:$servicePort...")
                val result = nativeRunHost("0.0.0.0", "SideInstallerHost", outputFile.absolutePath)

                mainHandler.post {
                    if (result == 0 && outputFile.exists() && outputFile.length() > 0) {
                        Log.d(TAG, "Pairing successful! File size: ${outputFile.length()} bytes")
                        onSuccess(outputFile)
                    } else {
                        Log.e(TAG, "Native host execution failed with code $result")
                        onError("Pairing failed (Exit code $result)")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Exception running host server", e)
                mainHandler.post { onError(e.localizedMessage ?: "Unknown native error") }
            }
        }.start()
    }

    private fun registerBonjourService(port: Int) {
        val serviceInfo = NsdServiceInfo().apply {
            serviceName = "SideInstallerHost"
            serviceType = "_remotepairing-pairable-host._tcp."
            setPort(port)
            setAttribute("v", "1")
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
    }

    fun startFileServer(file: File, port: Int) {
        stopFileServer()
        try {
            httpServer = HttpServer.create(InetSocketAddress(port), 0).apply {
                createContext("/pairing.pair") { exchange ->
                    val bytes = file.readBytes()
                    exchange.sendResponseHeaders(200, bytes.size.toLong())
                    exchange.responseBody.use { it.write(bytes) }
                }
                executor = null
                start()
            }
            Log.d(TAG, "Local file server started on port $port")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start local HTTP server", e)
        }
    }

    fun stopFileServer() {
        httpServer?.stop(0)
        httpServer = null
    }

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
