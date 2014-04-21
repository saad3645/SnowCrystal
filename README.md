Overview
========

SnowCrystal is a Unique ID generator inspired by Twitter's SnowFlake. Instead of being limited to 64 bits as in SnowFlake, SnowCrystal expands the ID to 120 bits, allowing for a bigger range of IDs, and nodes. SnowCrystal allows generating a large number of unique IDs every millisecond (4095 to be precise), without any risk of diplication, which makes it perfectly suitable for large distributed servers and applications that are required to handle a very high volume of requests. SnowCrystal utilizes an internal lock to ensure that the sequence value never rolls over, thus guranteeing uniqueness.

Structure of a SnowCrystal ID
-----------------------------

Each SnowCrystal ID is 120 bits or 15 bytes long, and in Big Endian format. The structure of an ID can be representated like this (sort of):


      |              Timestamp              |  Seq  |             Node            |
      |-------------------------------------|-------|-----------------------------|
      |    |    |    |    |    |    |    |  |  |    |    |    |    |    |    |    |
      |-------------------------------------|-------|-----------------------------|
      |  0    1    2    3    4    5    6    7     8 |  9   10   11   12   13   14 |
      |                                     |       |                             |


<br/>
Timestamp bits: 60

Sequence bits: 12

Node bits: 48


<br/>
**Timestamp**: 60 bits are allocated for the timestamp. This gives us a maximum value of 1152921504606846975 in milliseconds, roughly 36558901 years or upto 36558869 AD.
<br/>
**Sequence**: 12 bits are allocated for the sequence. This gives us a maximum of 4096 different sequences, or 4096 unique IDs per millisecond.
<br/>
**Node**: 48 bits are allocated for the node. This ensures that we can have a unique set of IDs for every MAC address on the planet (assuming 48 bit MAC addresses).


Why not just use UUID?
----------------------

You very well could, but you it does not sound as cool as SnowCrystal!
<br/>
Well to be serious SnowCrystal is designed for usage within large distributed apps and/or large clusters of nodes where each node is independently generating a _very large number_ of IDs. These nodes can be individual servers or just processes within a virtual machine. If you are hosting your application on a VM or a PAAS such as Heroku or CloudBees, then it is very likely that you are sharing your mac address with other apps and sometimes other instances of your own app. Since the MAC address is being shared between multiple instances of your application, if you are handling a very large number of requests, there is a minuscule chance that two UUIDs generated by two seperate instances will collide, especially if they are trying to genrate the UUIDs at the exact same moment. In these situations, SnowCrystal becomes your best friend. You can assign a Node Id for each of your SnowCrystal instances, and this will guarantee that no two instances will ever produce the same ID.
<br/>
Also SnowCrystal provides support to convert the IDs into nice Base64 strings (only 20 chars long), so they are more compact than UUIDs which is (at least traditionally) represented using Hex.

License
-------

Unless otherwise mentioned this project and its individual files are licensed under the Apache 2.0 license. See the LICENSE file for a full description.
