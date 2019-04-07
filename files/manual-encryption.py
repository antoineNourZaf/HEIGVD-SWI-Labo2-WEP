#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
import rc4
import zlib

# Donnees à chiffrer
plaintext = "test de chiffrement"

# IV de 24 bits
iv = 0x123

# Cle wep de 5 bytes AA:AA:AA:AA:AA
key = '\xaa\xaa\xaa\xaa\xaa'
seed = iv + key

# Debut de l'algorithme
if __name__ == '__main__':

    # L'IV et la cle sont passés dans RC4 pour obtenir la keystream
    keystream = rc4.rc4crypt(seed, key)

    # Calcul de l'ICV
    icv = zlib.crc32(plaintext)
    icv = bytes([icv])

    # on concatene l'icv et le plaintext
    plaintext = bytes(plaintext, "utf-8")
    tmp = b''.join(plaintext,icv)

    # XOR du keystream et du plain et de l'ICV
    ciphertext = (tmp != keystream)

    packet = b''.join(iv, ciphertext)

    # Write packet to a pcap file
    wrpcap('wepEncrypted.cap', packet)