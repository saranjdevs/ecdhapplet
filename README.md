```
## Sample public key:
B0
	41
	0412E625372BA12B97D8B199E8D9499D88589177EFCDD90FDA32C5126A276E0B73D3695E0011C27F6BB1AEC440D5597401D7336D42AD77A67B55246E15B3825A40
```	
```
## Commands to test ECDH shared secret generation
## Generate ECDH Keys for Applet (out put is public key as described in documents
cm>  /send A0 A3 00 00 00 
     => A0 A3 00 00 00                                     .....
 (2143 msec[SYS], 2143665 usecs[DEV])
     <= B0 41 04 84 73 6B A0 C9 89 09 89 EE 03 E6 D6 C5    .A..sk..........
    71 AA 25 1E 97 B6 54 DA 85 F6 05 8D E4 88 67 3D    q.%...T.......g=
    97 62 85 5E 1F EB A0 F8 C2 C5 2E 9B 19 A8 D8 E2    .b.^............
    0A 38 E4 88 24 8C 12 9E F4 D9 40 3C EB 6F D5 09    .8..$.....@<.o..
    A4 27 04 90 00                                     .'...
Status: No Error
```

```
## generate shared secret with someone else's Public key (used public key of above Sample Public Key)
cm>  /send A0 A4 00 00 43 B0 410412E625372BA12B97D8B199E8D9499D88589177EFCDD90FDA32C5126A276E0B73D3695E0011C27F6BB1AEC440D5597401D7336D42AD77A67B55246E15B3825A40
     => A0 A4 00 00 43 B0 41 04 12 E6 25 37 2B A1 2B 97    ....C.A...%7+.+.
    D8 B1 99 E8 D9 49 9D 88 58 91 77 EF CD D9 0F DA    .....I..X.w.....
    32 C5 12 6A 27 6E 0B 73 D3 69 5E 00 11 C2 7F 6B    2..j'n.s.i^....k
    B1 AE C4 40 D5 59 74 01 D7 33 6D 42 AD 77 A6 7B    ...@.Yt..3mB.w.{
    55 24 6E 15 B3 82 5A 40                            U$n...Z@
 (21182 msec[SYS], 21182077 usecs[DEV])
     <= 26 10 7A E0 65 CB D1 AD 76 16 6A 86 F1 CA 70 50    &.z.e...v.j...pP
    9C B1 67 A3 90 00                                  ..g...
Status: No Error
```

```
## AES ECB Cipher with 16 byte key (Keys supported are 16,24 and 32 bytes , you can use only one key at a time, if you want to use other key, then set again and do the encryption decryption)

cm>  /select A00000010001
     => 00 A4 04 00 06 A0 00 00 01 00 01 00                ............
 (4445 msec[SYS], 4444835 usecs[DEV])
     <= 90 00                                              ..
Status: No Error
```

```
## Set 16 byte KEY (p1 should be 01 for setting 16  byte key, 02 for setting 24 BYTE KEY, 03 for setting 32 byte key)
cm>  /send A01001001001020304050607080900010203040506
     => A0 10 01 00 10 01 02 03 04 05 06 07 08 09 00 01    ................
    02 03 04 05 06                                     .....
 (17544 msec[SYS], 17544772 usecs[DEV])
     <= 90 00                                              ..
Status: No Error
```

```
## Send data for Encryption (P1 ==00 means  Encryption, P2==00 means AES ECB Encryption)
cm>  /send A01200001001020304050607080900010203040506
     => A0 12 00 00 10 01 02 03 04 05 06 07 08 09 00 01    ................
    02 03 04 05 06                                     .....
 (51247 msec[SYS], 51247354 usecs[DEV])
     <= 54 18 BD 16 08 82 66 DA AB FF BC 2B 93 93 73 5D    T.....f....+..s]
    90 00                                              ..
Status: No Error
```

```
## Send Decryptioon (P1==01 meand AES decryption)
cm>  /send A0120100105418BD16088266DAABFFBC2B9393735D
     => A0 12 01 00 10 54 18 BD 16 08 82 66 DA AB FF BC    .....T.....f....
    2B 93 93 73 5D                                     +..s]
 (13358 msec[SYS], 13358065 usecs[DEV])
     <= 01 02 03 04 05 06 07 08 09 00 01 02 03 04 05 06    ................
    90 00 
```

```	
## CBC encryption
## Set key (no need to do if already done, but i restarted everything so had to do)
cm>  /send A01001001001020304050607080900010203040506
     => A0 10 01 00 10 01 02 03 04 05 06 07 08 09 00 01    ................
    02 03 04 05 06                                     .....
 (3891 msec[SYS], 3891197 usecs[DEV])
     <= 90 00                                              ..
Status: No Error
```

```
## P2== 01 (ICV is 00...00)
cm>  /send A01200011001020304050607080900010203040506
     => A0 12 00 01 10 01 02 03 04 05 06 07 08 09 00 01    ................
    02 03 04 05 06                                     .....
 (17181 msec[SYS], 17180903 usecs[DEV])
     <= 54 18 BD 16 08 82 66 DA AB FF BC 2B 93 93 73 5D    T.....f....+..s]
    90 00 	
	
cm>  /send A0120101105418BD16088266DAABFFBC2B9393735D 
     => A0 12 01 01 10 54 18 BD 16 08 82 66 DA AB FF BC    .....T.....f....
    2B 93 93 73 5D                                     +..s]
 (11150 msec[SYS], 11147454 usecs[DEV])
     <= 01 02 03 04 05 06 07 08 09 00 01 02 03 04 05 06    ................
    90 00 
```

```	
## Changing ICV and doing CBC encryption with same key

## Set ICV (16 Byte)
cm>  /send A01100001010000000000000000000000000000000
     => A0 11 00 00 10 10 00 00 00 00 00 00 00 00 00 00    ................
    00 00 00 00 00                                     .....
 (6014 msec[SYS], 6014867 usecs[DEV])
     <= 90 00   
```

```
## CBC encryption (P1==01 , ICV is 10000000000000000000000000000000)
 
 cm>  /send A01200011001020304050607080900010203040506
     => A0 12 00 01 10 01 02 03 04 05 06 07 08 09 00 01    ................
    02 03 04 05 06                                     .....
 (9933 msec[SYS], 9933507 usecs[DEV])
     <= A0 6B 4C 53 7C 81 4F 1D 1D B7 52 DA 53 9F ED 47    .kLS|.O...R.S..G
    90 00                                              ..
Status: No Error
```

```
## CBC Decryption
cm>  /send A012010110A06B4C537C814F1D1DB752DA539FED47
     => A0 12 01 01 10 A0 6B 4C 53 7C 81 4F 1D 1D B7 52    ......kLS|.O...R
    DA 53 9F ED 47                                     .S..G
 (12831 msec[SYS], 12831531 usecs[DEV])
     <= 01 02 03 04 05 06 07 08 09 00 01 02 03 04 05 06    ................
    90 00  
```	
	
```	
## Random Number Generation (True Random)

cm>  /select A00000010001
     => 00 A4 04 00 06 A0 00 00 01 00 01 00                ............
 (1402 msec[SYS], 1401874 usecs[DEV])
     <= 90 00                                              ..
Status: No Error 
```

```
## A7 command is used for random number generation (LC should be 01 and length should be 01 to 7F including 01 and 7F
#Generate 22 bytes random
cm>  /send A0A700000116  
     => A0 A7 00 00 01 16                                  ......
 (11313 msec[SYS], 11313502 usecs[DEV])
     <= 7D FB 4C EB 8A A9 08 A3 D8 9C DA 6F F9 EE 05 CB    }.L........o....
    84 A9 F8 C3 69 D2 90 00                            ....i...
Status: No Error
```

```
## generate 16 byte random
cm>  /send A0A700000110
     => A0 A7 00 00 01 10                                  ......
 (1165 msec[SYS], 1165317 usecs[DEV])
     <= 39 14 83 A6 9C 8E 6C 23 B8 BC 95 CA 9B C7 96 A4    9.....l#........
    90 00                                              ..
Status: No Error
```

```
## generate 1 byte random
cm>  /send A0A700000101
     => A0 A7 00 00 01 01                                  ......
 (1492 msec[SYS], 1492258 usecs[DEV])
     <= BD 90 00                                           ...
Status: No Error
```

```
## generate 7F bytes radom
cm>  /send A0A70000017F
     => A0 A7 00 00 01 7F                                  ......
 (902396 usec[SYS], 902198 usecs[DEV])
     <= 98 C2 83 33 3D FF 8A 25 8E D5 EF 82 10 C4 00 F2    ...3=..%........
    19 DB 64 0D 35 86 A4 CA C9 A8 EA 3A F6 E9 08 76    ..d.5......:...v
    C0 52 BB D6 70 17 31 63 36 B3 CA 8F 13 3A 1C 24    .R..p.1c6....:.$
    F6 EB 39 7B 26 05 34 EE DF DD E1 8F 40 2C DD 1B    ..9{&.4.....@,..
    65 AD CE 29 D0 E8 EC A7 0D 48 C1 87 95 74 2C B6    e..).....H...t,.
    F4 DC AC 4E 27 92 DB 0C 48 5C 39 04 6D 07 2B 93    ...N'...H\9.m.+.
    CD FE 44 96 24 1B C2 D9 59 BC 5C D3 5E 1A 3B 90    ..D.$...Y.\.^.;.
    59 D6 46 EE 01 D5 A2 0C 4A 4E 79 00 44 21 FB 90    Y.F.....JNy.D!..
    00                                                 .
Status: No Error
```

```
## incorrect lengths
cm>  /send A0A7000001FF
     => A0 A7 00 00 01 FF                                  ......
 (1180 msec[SYS], 1180071 usecs[DEV])
     <= 6A 80                                              j.
Status: Wrong data
cm>  /send A0A700000100
     => A0 A7 00 00 01 00                                  ......
 (1182 msec[SYS], 1181063 usecs[DEV])
     <= 6A 80                                              j.
Status: Wrong data	
```

```
############################## HASH ###########################
```

```
## Generate SHA 256 hash (P1==01) MAX length of input data 127 and minimum 01
cm>  /send A0A6010010A06B4C537C814F1D1DB752DA539FED47
     => A0 A6 01 00 10 A0 6B 4C 53 7C 81 4F 1D 1D B7 52    ......kLS|.O...R
    DA 53 9F ED 47                                     .S..G
 (20473 msec[SYS], 20473140 usecs[DEV])
     <= B3 AA 20 30 D1 3F 04 57 CA 35 BD 36 52 97 28 A6    .. 0.?.W.5.6R.(.
    30 8C 97 A3 1B 9A 8D 76 A1 9F 02 2D DE 3B 41 0E    0......v...-.;A.
    90 00                                              ..
Status: No Error
```

```
## Generate SHA 1 hash (P1==00)
cm>  /send A0A6000010A06B4C537C814F1D1DB752DA539FED47
     => A0 A6 00 00 10 A0 6B 4C 53 7C 81 4F 1D 1D B7 52    ......kLS|.O...R
    DA 53 9F ED 47                                     .S..G
 (11418 msec[SYS], 11418588 usecs[DEV])
     <= D9 4B 33 20 82 72 21 F3 1D CB 73 1B 2A DB DF 9A    .K3 .r!...s.*...
    BA 17 1F 60 90 00                                  ...`..
Status: No Error
```

```
## Generate SHA 2512 hash (P1==02)
cm>  /send A0A6020010A06B4C537C814F1D1DB752DA539FED47
     => A0 A6 02 00 10 A0 6B 4C 53 7C 81 4F 1D 1D B7 52    ......kLS|.O...R
    DA 53 9F ED 47                                     .S..G
 (10063 msec[SYS], 10063726 usecs[DEV])
     <= FF DE 49 52 41 D3 8D FD 5B AA DC 99 8C C8 C4 8B    ..IRA...[.......
    C5 C1 3F C9 DE E2 A3 8D 67 EE 5F E2 5E 8B 77 AA    ..?.....g._.^.w.
    03 5F A8 19 E0 3F 64 8D D1 3F C1 65 3F 8B D7 BC    ._...?d..?.e?...
    F4 C2 D3 BA EC 95 7E 24 93 13 11 DE 84 17 BE 9D    ......~$........
    90 00                                              ..
Status: No Error hash of 15 bytes data
```


```
cm>  /send A0A601000FA06B4C537C814F1D1DB752DA539FED
     => A0 A6 01 00 0F A0 6B 4C 53 7C 81 4F 1D 1D B7 52    ......kLS|.O...R
    DA 53 9F ED                                        .S..
 (11054 msec[SYS], 11054703 usecs[DEV])
     <= D5 5A AE AD 1B 34 80 41 99 4E F3 67 DC 60 21 4C    .Z...4.A.N.g.`!L
    6A 4D F8 00 3D 7A BB 44 EC A1 79 E7 18 CA C3 5E    jM..=z.D..y....^
    90 00                                              ..
Status: No Error
```

```
## Hash of 1 byte data
cm>  /send A0A6010001A0
     => A0 A6 01 00 01 A0                                  ......
 (8824 msec[SYS], 8824616 usecs[DEV])
     <= C1 9A 79 7F A1 FD 59 0C D2 E5 B4 2D 1C F5 F2 46    ..y...Y....-...F
    E2 9B 91 68 4E 2F 87 40 4B 81 DC 34 5C 7A 56 A0    ...hN/.@K..4\zV.
    90 00  
```	
	
```	
## ############################ HMAC ################################
```

```
## Set HMAC1 key (P1==01) - Key length 08
cm>  /send A0A80100080102030405060708
     => A0 A8 01 00 08 01 02 03 04 05 06 07 08             .............
 (3631 msec[SYS], 3631314 usecs[DEV])
     <= 90 00     
```

```
## Set HAMC 256 key (P1==02)- key length 08	
cm>  /send A0A80200081112131415161718
     => A0 A8 02 00 08 11 12 13 14 15 16 17 18             .............
 (1336 msec[SYS], 1336291 usecs[DEV])
     <= 90 00  
```
 

``` 
## Set HMAC 512 key (P1== 02)- Key Length 16
cm>  /send A0A803001011121314151617180102030405060708
     => A0 A8 03 00 10 11 12 13 14 15 16 17 18 01 02 03    ................
    04 05 06 07 08                                     .....
 (1153 msec[SYS], 1153180 usecs[DEV])
     <= 90 00 
```

``` 
## HMAC 1 generation P1 ==01 output HMAC 20 byes
cm>  /send A0A901007F10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010
     => A0 A9 01 00 7F 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10                                        ....
 (3035 usec[SYS], 2774 usecs[DEV])
     <= 41 21 6A A8 BB 85 7D FE 66 05 FD 09 3A 12 EB 48    A!j...}.f...:..H
    8F B1 02 D0 90 00                                  ......
Status: No Error 
```

```
## HMAC 256 generation P1==02 output HMAC = 32 bytes
cm>  /send A0A902007F10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010
     => A0 A9 02 00 7F 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10                                        ....
 (1159 usec[SYS], 1080 usecs[DEV])
     <= DD 30 E4 1D 6E A9 8F 78 27 B3 DD 29 40 A5 EF 24    .0..n..x'..)@..$
    7F D3 33 9F 10 16 41 F3 28 6C 80 53 9C 14 D9 7B    ..3...A.(l.S...{
    90 00                                              ..
Status: No Error
```

```
## HMAC 512 generation P1==03 output HMAC =64 bytes
cm>  /send A0A903007F10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010
     => A0 A9 03 00 7F 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10    ................
    10 10 10 10                                        ....
 (2093 usec[SYS], 1862 usecs[DEV])
     <= 1A FA 5A 28 B3 1A B4 E3 D4 01 92 0F 1D A4 8E D2    ..Z(............
    7F E2 F0 55 51 22 B4 8E 94 B7 08 17 DB 82 10 8B    ...UQ"..........
    07 C9 20 61 9D 43 91 6D 64 CA C0 87 A0 97 DB 5B    .. a.C.md......[
    EB E9 75 E2 0F FA E1 F1 1C E0 70 A8 53 EA 30 6A    ..u.......p.S.0j
    90 00                                              ..
Status: No Error
```

```
## ECDSA gen key pair = Output public Keys

cm>  /send A0A0000000
     => A0 A0 00 00 00                                     .....
 (218185 usec[SYS], 218095 usecs[DEV])
     <= B0 41 04 ED 20 74 D7 5A 74 32 A1 AC 92 4F 2D BE    .A.. t.Zt2...O-.
    60 74 E4 C8 C5 DF 36 69 4C 7A B5 84 6D 9B 6A BF    `t....6iLz..m.j.
    61 45 F0 BC F8 CD B6 FB A6 27 B0 32 80 7D 95 15    aE.......'.2.}..
    52 08 C0 D4 15 56 C4 C2 F1 59 D7 8E 01 13 C0 83    R....V...Y......
    6E 1D B3 90 00     
```

```	
## ECDSA Sign data
cm>  /send A0A100801001020304050607080102030405060708
     => A0 A1 00 80 10 01 02 03 04 05 06 07 08 01 02 03    ................
    04 05 06 07 08                                     .....
 (12657 usec[SYS], 12478 usecs[DEV])
     <= B1 46 30 44 02 20 31 68 34 36 02 B0 04 EE 70 63    .F0D. 1h46....pc
    46 69 43 55 B1 3E F8 AC 68 6F 2E C9 96 C4 4D 23    FiCU.>..ho....M#
    26 4C 32 28 60 D3 02 20 78 9B 52 A5 B1 8A E5 60    &L2(`.. x.R....`
    2C 90 81 07 85 67 86 AD 99 D7 9A D9 E5 0F 30 13    ,....g........0.
    88 37 82 97 1C A3 FC F3 90 00   	
```


```	
## ECDA verify signed data (pre-requisite , data is signed using the sign command, so that the applet have input data to verify) , output 01 if verified, 00 if not verified
cm>  /send A049000046304402203168343602B004EE706346694355B13EF8AC686F2EC996C44D23264C322860D30220789B52A5B18AE5602C908107856786AD99D79AD9E50F3013883782971CA3FCF3
     => A0 49 00 00 46 30 44 02 20 31 68 34 36 02 B0 04    .I..F0D. 1h46...
    EE 70 63 46 69 43 55 B1 3E F8 AC 68 6F 2E C9 96    .pcFiCU.>..ho...
    C4 4D 23 26 4C 32 28 60 D3 02 20 78 9B 52 A5 B1    .M#&L2(`.. x.R..
    8A E5 60 2C 90 81 07 85 67 86 AD 99 D7 9A D9 E5    ..`,....g.......
    0F 30 13 88 37 82 97 1C A3 FC F3                   .0..7......
 (12353 usec[SYS], 12248 usecs[DEV])
     <= 01 90 00                                           ...
Status: No Error
```

```
## ECDA verify signed data (pre-requisite , data is signed using the sign command, so that the applet have input data to verify) , output 01 if verified, 00 if not verified
## Send command for input data 
## pre-requisite do select applet command
cm>  /select A00000010001
     => 00 A4 04 00 06 A0 00 00 01 00 01 00                ............
 (3411 usec[SYS], 3201 usecs[DEV])
     <= 90 00                                              ..
Status: No Error
```

```
## USer set input data to do perform ecc verify command
cm>  /send A04800801001020304050607080102030405060708
     => A0 48 00 80 10 01 02 03 04 05 06 07 08 01 02 03    .H..............
    04 05 06 07 08                                     .....
 (2436 usec[SYS], 2289 usecs[DEV])
     <= 90 00                                              ..
Status: No Error
```

```
## now send ECC verify command with the sig
cm>  /send A049000046304402203168343602B004EE706346694355B13EF8AC686F2EC996C44D23264C322860D30220789B52A5B18AE5602C908107856786AD99D79AD9E50F3013883782971CA3FCF3
     => A0 49 00 00 46 30 44 02 20 31 68 34 36 02 B0 04    .I..F0D. 1h46...
    EE 70 63 46 69 43 55 B1 3E F8 AC 68 6F 2E C9 96    .pcFiCU.>..ho...
    C4 4D 23 26 4C 32 28 60 D3 02 20 78 9B 52 A5 B1    .M#&L2(`.. x.R..
    8A E5 60 2C 90 81 07 85 67 86 AD 99 D7 9A D9 E5    ..`,....g.......
    0F 30 13 88 37 82 97 1C A3 FC F3                   .0..7......
 (10042 usec[SYS], 9938 usecs[DEV])
     <= 01 90 00                                           ...
```
	