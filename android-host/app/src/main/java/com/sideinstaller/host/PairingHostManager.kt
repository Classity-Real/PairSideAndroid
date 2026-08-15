package com.sideinstaller.host

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.io.File
import java.io.OutputStream
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket

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
    private var serverSocket: ServerSocket? = null
    private var serverThread: Thread? = null
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

    // Minimal single-endpoint HTTP server using raw sockets (Android has no com.sun.net.httpserver)
    fun startFileServer(file: File, port: Int) {
        stopFileServer()
        try {
            serverSocket = ServerSocket(port)
            serverThread = Thread {
                Log.d(TAG, "Local file server started on port $port")
                while (!Thread.currentThread().isInterrupted) {
                    try {
                        val client = serverSocket?.accept() ?: break
                        handleClient(client, file)
                    } catch (e: Exception) {
                        if (serverSocket?.isClosed == true) break
                        Log.e(TAG, "Error accepting client", e)
                    }
                }
            }
            serverThread?.start()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start local HTTP server", e)
        }
    }

    private fun handleClient(client: Socket, file: File) {
        Thread {
            try {
                client.getInputStream().bufferedReader().readLine() // read request line, ignore rest

                val out: OutputStream = client.getOutputStream()
                val bytes = file.readBytes()
                val header = "HTTP/1.1 200 OK\r\n" +
                        "Content-Type: application/octet-stream\r\n" +
                        "Content-Length: ${bytes.size}\r\n" +
                        "Connection: close\r\n\r\n"
                out.write(header.toByteArray())
                out.write(bytes)
                out.flush()
            } catch (e: Exception) {
                Log.e(TAG, "Error serving client", e)
            } finally {
                client.close()
            }
        }.start()
    }

    fun stopFileServer() {
        try {
            serverThread?.interrupt()
            serverSocket?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping file server", e)
        }
        serverSocket = null
        serverThread = null
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
