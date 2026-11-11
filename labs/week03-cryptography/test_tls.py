import socket
import ssl
import certifi

hostname = "example.com"
context = ssl.create_default_context(cafile=certifi.where())

with socket.create_connection((hostname, 443), timeout=15) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
        cert = secure_sock.getpeercert()

        print("TLS version:", secure_sock.version())
        print("Cipher:", secure_sock.cipher()[0])
        print("Subject:", cert.get("subject"))
        print("Issuer:", cert.get("issuer"))
        print("Valid from:", cert.get("notBefore"))
        print("Valid until:", cert.get("notAfter"))
        print("Certificate verification: SUCCESS")
