# reverse_ssh.bro

Bro script to detect Reverse SSH tunnels based on keystroke packet lengths.

Concept derived from Jeff Atkinson and John Althouse.

This script calculates the expected packet length based on the ciphers utilized in the initial handshake. It is assumed that the same ciphers are utilized on the "inside" tunnel as well to derive the full packet length of the reverse ssh tunnel; since bro will not have visibility into that handshake process.
