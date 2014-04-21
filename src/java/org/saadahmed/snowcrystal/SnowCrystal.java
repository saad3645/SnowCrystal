/*
 * Copyright (c) 2013 Saad Ahmed
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.saadahmed.snowcrystal;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.saadahmed.commons.codec.Base64Hex;
import org.apache.commons.codec.digest.DigestUtils;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.Random;
import java.util.logging.Logger;


/**
 *
 * @author Saad Ahmed
 */
public class SnowCrystal {

	/*
	 * Timestamp:        60 bits
	 * Sequence:         12 bits
	 * SnowCrystalNode:  48 bits
	 *                  ------------------
	 * Total:           120 bits = 15 bytes
	 *
	 * Total size when converted to Base64: 120/6 = 20 chars
	 *
	 * Graphical representation (sort of) =>
	 *
	 * |              Timestamp              |  Seq  |             Node            |
	 * |-------------------------------------|-------|-----------------------------|
	 * |    |    |    |    |    |    |    |  |  |    |    |    |    |    |    |    |
	 * |-------------------------------------|-------|-----------------------------|
	 * |  0    1    2    3    4    5    6    7     8 |  9   10   11   12   13   14 |
	 * |                                     |       |                             |
	 *
	 */

	// Do NOT change these values unless absolutely necessary!!
	// We are doing some bit-shifting and bit-masking based on the current
	// values, so if these values are changed, you have to modify the
	// constructor and getter/setter methods too, otherwise everything will break!
	public static final int TIMESTAMP_BITS_LENGTH = 60;
	public static final int SEQUENCE_BITS_LENGTH = 12;
	public static final int NODE_BITS_LENGTH = 48;
	public static final int SNOWCRYSTAL_BITS_LENGTH = TIMESTAMP_BITS_LENGTH + SEQUENCE_BITS_LENGTH + NODE_BITS_LENGTH;

	public static final int TIMESTAMP_LENGTH = TIMESTAMP_BITS_LENGTH / 8;
	public static final int SEQUENCE_LENGTH = SEQUENCE_BITS_LENGTH / 8;
	public static final int NODE_LENGTH = NODE_BITS_LENGTH / 8;
	public static final int SNOWCRYSTAL_LENGTH = SNOWCRYSTAL_BITS_LENGTH / 8;

	public static final int TIMESTAMP_OFFSET = 0;
	public static final int SEQUENCE_0_OFFSET = 7;
	public static final int SEQUENCE_1_OFFSET = 8;
	public static final int NODE_OFFSET = 9;

	private static Logger logger = Logger.getLogger("SnowCrystal");

	private static long lastTimestamp;
	private static short lastSequence;
	private static byte[] nodeId;


	private final byte[] binary;



	protected SnowCrystal(long timestamp, short sequence, byte[] nodeId) {
		if (sequence > 4095) {
			throw new IllegalArgumentException("Sequence cannot be greater than 2^12 - 1 = 4095. Sequence found: " + sequence);
		}

		if (nodeId == null) {
			throw new NullPointerException("SnowCrystal Node id is null");
		}
		if (nodeId.length != NODE_LENGTH) {
			throw new IllegalArgumentException("Invalid SnowCrystal Node size. Expected: " + NODE_LENGTH +
					", Found: " + nodeId.length);
		}

		long ts = timestamp << 4;
		byte[] tsBytes = ByteBuffer.allocate(8).putLong(ts).array();
		byte[] seqBytes = ByteBuffer.allocate(2).putShort(sequence).array();
		byte commonByte = (byte)(tsBytes[7] | seqBytes[0]);

		ByteBuffer buffer = ByteBuffer.allocate(SNOWCRYSTAL_LENGTH);
		buffer.putLong(TIMESTAMP_OFFSET, ts);
		buffer.put(SEQUENCE_0_OFFSET, commonByte);
		buffer.put(SEQUENCE_1_OFFSET, seqBytes[1]);

		this.binary = buffer.array();
		System.arraycopy(nodeId, 0, this.binary, NODE_OFFSET, NODE_LENGTH);
	}


	protected SnowCrystal(byte[] binary) {
		this.binary = binary;
	}


	@Override
	public boolean equals(Object object) {
		return (this.getClass().equals(object.getClass()) && this.toString().equals(object.toString()));
	}

	@Override
	public int hashCode() {
		return this.toString().hashCode();
	}

	public long timestamp() {
		long ts = ByteBuffer.wrap(this.binary).getLong(TIMESTAMP_OFFSET);
		return (ts >>> 4);
	}

	public short sequence() {
		short seq = ByteBuffer.wrap(this.binary).getShort(SEQUENCE_0_OFFSET);
		short mask = 4095;
		return (short)(seq & mask);
	}

	public byte[] nodeId() {
		byte[] nodeId = new byte[NODE_LENGTH];
		System.arraycopy(this.binary, NODE_OFFSET, nodeId, 0, NODE_LENGTH);
		return nodeId;
	}

	public String nodeIdHex() {
		return Hex.encodeHexString(nodeId());
	}

	public byte[] unwrap() {
		return this.binary;
	}


	/**
	 * By default, toString() encodes the binary data in Base64Hex.
	 * To see the difference between Base64 and Base64Hex, please see the docs for the Base64Hex class.
	 *
	 * @return Base64Hex encoded string of the SnowCrystal
	 */
	@Override
	public String toString() {
		return toString(true);
	}

	public String toString(boolean base64Hex) {
		if (base64Hex) {
			return Base64Hex.encodeBase64HexString(this.binary);
		}

		else {
			return Base64.encodeBase64URLSafeString(this.binary);
		}
	}

	public String toHexString() {
		return Hex.encodeHexString(this.binary);
	}


	public static void initializeWithIpAddress() {
		initialize(getIpAddress());
	}

	public static synchronized void initializeWithMacAddress() {
		initialize(getMacAddress());
	}

	public static synchronized void initialize(String nodeId) {
		try {
			initialize(Hex.decodeHex(nodeId.toCharArray()));
		}
		catch (DecoderException e) {
			logger.severe("Invalid Node Id: " + nodeId + ", HexDecoderException: " + e.getMessage());
			logger.warning("Initializing SnowCrystal Node using host mac Address");
			initializeWithMacAddress();
		}
	}

	public static synchronized void initialize(byte[] nodeId) {
		if (nodeId == null) {
			logger.severe("Node Id is null");
			logger.warning("Initializing SnowCrystal Node using host mac address");
			SnowCrystal.nodeId = getMacAddress();
		}
		else if (nodeId.length != NODE_LENGTH) {
			logger.severe("Invalid Node Id size. Expected: " + NODE_LENGTH + ", Found: " + nodeId.length);
			logger.warning("Initializing SnowCrystal Node using host mac address");
			SnowCrystal.nodeId = getMacAddress();
		}
		else {
			SnowCrystal.nodeId = nodeId;
		}

		SnowCrystal.lastTimestamp = System.currentTimeMillis() - 1;
		SnowCrystal.lastSequence = 0;
	}


	public static String getNodeId() {
		return Hex.encodeHexString(nodeId);
	}

	protected static void setStartingTimestamp(long timestamp) {
		SnowCrystal.lastTimestamp = timestamp;
	}

	protected static void setNodeId(byte[] nodeId) throws IllegalArgumentException {
		if (nodeId == null) {
			throw new NullPointerException("SnowCrystal Node Id not specified");
		}
		if (nodeId.length != NODE_LENGTH) {
			throw new IllegalArgumentException("Invalid SnowCrystal Node Id size. Expected: " + NODE_LENGTH +
					", Found: " + nodeId.length);
		}

		SnowCrystal.nodeId = nodeId;
	}

	protected static void setStartingSequence(short sequence) {
		SnowCrystal.lastSequence = sequence;
	}


	public static SnowCrystal newId() {
		return generate();
	}

	public static byte[] newIdBinary() {
		return SnowCrystal.newId().unwrap();
	}

	public static String newIdString() {
		return SnowCrystal.newId().toString();
	}

	public static String hexString() {
		return SnowCrystal.newId().toHexString();
	}

	public static String md5Hex() {
		return DigestUtils.md5Hex(SnowCrystal.newId().unwrap());
	}

	public static String md5Base64UrlSafe() {
		return Base64.encodeBase64URLSafeString(DigestUtils.md5(SnowCrystal.newId().unwrap()));
	}

	public static String sha1Hex() {
		return DigestUtils.shaHex(SnowCrystal.newId().unwrap());
	}

	public static String sha1Base64UrlSafe() {
		return Base64.encodeBase64URLSafeString(DigestUtils.sha(SnowCrystal.newId().unwrap()));
	}

	public static String sha256Hex() {
		return DigestUtils.sha256Hex(SnowCrystal.newId().unwrap());
	}

	public static String sha256Base64UrlSafe() {
		return Base64.encodeBase64URLSafeString(DigestUtils.sha256(SnowCrystal.newId().unwrap()));
	}

	public static String sha384Hex() {
		return DigestUtils.sha384Hex(SnowCrystal.newId().unwrap());
	}

	public static String sha384Base64UrlSafe() {
		return Base64.encodeBase64URLSafeString(DigestUtils.sha384(SnowCrystal.newId().unwrap()));
	}

	public static String sha512Hex() {
		return DigestUtils.sha512Hex(SnowCrystal.newId().unwrap());
	}

	public static String sha512Base64URLSafe() {
		return Base64.encodeBase64URLSafeString(DigestUtils.sha512(SnowCrystal.newId().unwrap()));
	}

	public static SnowCrystal createFromBytes(byte[] binary) {
		return new SnowCrystal(binary);
	}

	public static SnowCrystal createFromString(String string) {
		return new SnowCrystal(Base64Hex.decodeBase64Hex(string));
	}

	public static SnowCrystal createFromHexString(String hexString) throws DecoderException {
		return new SnowCrystal(Hex.decodeHex(hexString.toCharArray()));
	}

	public static SnowCrystal createFromBase64String(String base64String) {
		return new SnowCrystal(Base64.decodeBase64(base64String));
	}


	public static byte[] getIpAddress() {
		byte[] address = new byte[NODE_LENGTH];

		try {
			byte[] ipAddress = InetAddress.getLocalHost().getAddress();

			// NODE_LENGTH = 6
			if (ipAddress.length < SnowCrystal.NODE_LENGTH) {
				System.arraycopy(ipAddress, 0, address, 0, ipAddress.length);
				return address;
			}

			// NODE_LENGTH = 6
			else if (ipAddress.length == SnowCrystal.NODE_LENGTH) {
				return ipAddress;
			}

			// NODE_LENGTH = 6
			else if (ipAddress.length > SnowCrystal.NODE_LENGTH && ipAddress.length == 8) {
				System.arraycopy(ipAddress, 0, address, 0, SnowCrystal.NODE_LENGTH /2);
				System.arraycopy(ipAddress, (SnowCrystal.NODE_LENGTH /2) + 2, address, (SnowCrystal.NODE_LENGTH /2), SnowCrystal.NODE_LENGTH /2);
				return address;
			}

			// NODE_LENGTH = 6
			else if (ipAddress.length > SnowCrystal.NODE_LENGTH && ipAddress.length != 8) {
				throw new UnknownHostException("Unknown host address type");
			}
		}
		catch (Exception e) {
			e.printStackTrace();
			new SecureRandom().nextBytes(address);
		}

		return address;
	}


	public static byte[] getMacAddress() {
		byte[] address = new byte[NODE_LENGTH];

		try {
			InetAddress ip = InetAddress.getLocalHost();
			byte[] macAddress = NetworkInterface.getByInetAddress(ip).getHardwareAddress();

			// NODE_LENGTH = 6
			if (macAddress.length < SnowCrystal.NODE_LENGTH) {
				System.arraycopy(macAddress, 0, address, 0, macAddress.length);
				return address;
			}

			// NODE_LENGTH = 6
			else if (macAddress.length == SnowCrystal.NODE_LENGTH) {
				return macAddress;
			}

			// NODE_LENGTH = 6
			else if (macAddress.length > SnowCrystal.NODE_LENGTH && macAddress.length == 8) {
				System.arraycopy(macAddress, 0, address, 0, SnowCrystal.NODE_LENGTH /2);
				System.arraycopy(macAddress, (SnowCrystal.NODE_LENGTH /2) + 2, address, (SnowCrystal.NODE_LENGTH /2), SnowCrystal.NODE_LENGTH /2);
				return address;
			}

			// NODE_LENGTH = 6
			else if (macAddress.length > SnowCrystal.NODE_LENGTH && macAddress.length != 8) {
				throw new UnknownHostException("Unknown host address type");
			}
		}

		catch (Exception e) {
			e.printStackTrace();
			new Random().nextBytes(address);
		}

		return address;
	}


	private static synchronized SnowCrystal generate() throws ClockMovedBackException {
		if (nodeId == null) {
			initializeWithMacAddress();
		}

		long timestamp = System.currentTimeMillis();
		short sequence = 0;

		if (timestamp < lastTimestamp) {
			throw new ClockMovedBackException("Current system time [" + new Timestamp(timestamp) +
					"] < last generated timestamp [" + new Timestamp(lastTimestamp) + "]");
		}

		if (timestamp == lastTimestamp) {
			// Sequence rollover protection
			// if current sequence = 00001111 11111111 = 4095, incrementing the
			// value would make it rollover beyond the 12 bits allocated for
			// the sequence. So force the thread to go sleep for exactly
			// 1 millisecond while it still has the lock. After the thread
			// wakes up, the clock will have moved forward by 1 millisecond,
			// and then we can safely increment the sequence without repeating.
			if (lastSequence == 4095) {
				do {
					try {
						Thread.sleep(1);
					}
					catch (InterruptedException e) {
						e.printStackTrace();
					}

					timestamp = System.currentTimeMillis();

					// check to make sure the clock has indeed moved forward
					// in case we were woken up by an interruption
				} while(timestamp == lastTimestamp);

				lastSequence = -1;
			}

			sequence = (short)(lastSequence + 1);
		}

		// don't forget to update the last used timestamp and sequence!
		lastTimestamp = timestamp;
		lastSequence = sequence;

		return new SnowCrystal(timestamp, sequence, SnowCrystal.nodeId);
	}

}
