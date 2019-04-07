#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
import rc4
import zlib
import binascii

# Debut de l'algorithme
if __name__ == '__main__':

    # Donnees à chiffrer
    plaintext = "test de chiffrement avec message long"

    # Cle wep de 5 bytes AA:AA:AA:AA:AA
    key = '\xaa\xaa\xaa\xaa\xaa'

    # Trame de départ pour avoir le template
    arp = rdpcap('arp.cap')[0]

    # La seed est composé de IV + clé
    seed = arp.iv + key

    # Calcul de l'ICV
    icv = binascii.crc32(plaintext)
    icv_clair = struct.pack('<i', icv)

    # on concatene l'icv et le plaintext
    plaintext = plaintext + icv_clair

    # Chiffrement par RC4
    ciphertext = rc4.rc4crypt(plaintext, seed)

    # Prerpare les datas
    arp.wepdata = ciphertext[:-4]
    (arp.icv,) = struct.unpack('!L', ciphertext[-4:])

    # Write packet to a pcap file
    wrpcap('wepEncrypted.cap', arp)
