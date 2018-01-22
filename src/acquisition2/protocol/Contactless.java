/** copyright CVM */

package acquisition2.protocol;

import static com.riscure.signalanalysis.data.SimpleVerdict.INCONCLUSIVE;
import static com.riscure.signalanalysis.data.SimpleVerdict.SUCCESSFUL;
import static com.riscure.util.HexUtils.*;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.IOException;

import acquisition2.protocol.BasicProtocol;
import acquisition2.protocol.Contactless.Contactless_ProtocolSettings.Mode;
import com.riscure.beans.annotation.DisplayName;
import com.riscure.beans.annotation.ShortDescription;
import com.riscure.osgi.legacy.Service;
import com.riscure.protocol.ProtocolException;

import acquisition2.protocol.SM4;

@Service("Contactless Card")
public class Contactless extends BasicProtocol {

	private static final int STATUS_WORD_LENGTH = 2;

	private static final String ATR = "3B 8D 80 01";
	private static final String DDF1NAME = "D1 56 00 01 37";
	private static final String mcck = "414A4341353830343536303035363731";
	private static final String id_mcck = "00";
	private static final String UserID = "D6D0B9FAB2D0BCB2C8CBC1AABACFBBE1";

	/**
	 * Creates a protocol with input length 8 bytes and expected output length 8
	 * bytes.
	 */
	public Contactless() {
		super(4, 107);
		this.setSettingsBean(new Contactless_ProtocolSettings());
		addPhase("Select command");
		addPhase("Crypto command");
	}

	@Override
	protected void init() throws IOException {
		phase("Select command");
		command(concat("00 A4 04 00 05", hex(DDF1NAME)));
	}

	@Override
	protected void run() throws IOException {
		Contactless_ProtocolSettings settings = (Contactless_ProtocolSettings) this.settings;

		// Verdict defaults to inconclusive
		verdict(INCONCLUSIVE);

		// Sending crypto command
		phase("Crypto command");
		byte[] cmd;
		byte[] response;
		Mode mode = settings.getMode();
		if (Mode.InternalAuth == mode) {
			cmd = hex("00 88 00 00 04 6C CE 03 3F");
			cmd = randomize(cmd, 5, getInputLength());
			byte[] inputData = sub(cmd, 5, getInputLength());
			addDataIn(inputData);
			response = command(cmd);
			// Checking response
			byte[] outputData = sub(response, 0, getOutputLength());
			addDataOut(outputData);

			if (endsWith(response, "90 00")) {
				// Card reports success
				// Unless we determine the crypto was incorrect the verdict is normal
				verdict(SUCCESSFUL);
			}
		} else {
			cmd = hex("00 84 00 00 08");
			response = command(cmd);
			byte[] CRandom = sub(response, 0, response.length - STATUS_WORD_LENGTH);
			addDataIn(CRandom);
			byte[] TRandom = hex("00 FF FF FF FF FF FF FF");
			TRandom = randomize(TRandom, 0, TRandom.length);
			byte[] SessionKey = SM4EncryptECB(hex(mcck), rightExtend(CRandom, 16));
			byte[] tmpdata = SM4EncryptECB(SessionKey, rightExtend(TRandom, 16));

			byte[] sdata00 = new byte[8];
			for (int i = 0; i < 8; i++) {
				sdata00[i] = (byte) (tmpdata[i] ^ tmpdata[i + 8]);
			}
			addDataOut(SessionKey);
			cmd = concat(hex("00 82 00"), hex(id_mcck), hex("11"), sdata00, TRandom, hex("01"));
			response = command(cmd);
			// Checking response

			if (endsWith(response, "90 00")) {
				// Card reports success
				// Unless we determine the crypto was incorrect the verdict
				// is
				// normal
				verdict(SUCCESSFUL);
			}
			if (Mode.SM2GenKeyPair == mode) {
				byte[] sHashData = hex(
						"00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF");
				sHashData = randomize(sHashData, 0, 32);
				cmd = concat(hex("80 50 00 00 20"), sHashData);
				response = command(cmd);
				if (endsWith(response, "90 00")) {
					// Card reports success
					// Unless we determine the crypto was incorrect the verdict is normal
					verdict(SUCCESSFUL);
					byte[] PubKey = sub(response, 0, 64);
					byte[] PubSign = sub(response, 64, 64);
					byte[] HashSign = sub(response, 128, 64);
					//                    byte[] ZA = CalcZA(hex(UserID), concat(hex("04"), PubKey));
					//                    byte[] PubHashData = SM3(concat(ZA, PubKey));
					//SM2Verify???
				}
			}
		}
	}

	private static byte[] SM4EncryptECB(byte[] key, byte[] plaintext) {
		SM4 sm4 = new SM4();
		byte[] cipher = intsToBytes(sm4.Encrypt(bytesToInts(plaintext, 0), bytesToInts(key, 0)));
		return cipher;
	}

	public static int[] bytesToInts(byte[] src, int offset) {
		int[] value = new int[4];
		for (int i = 0; i < 4; i++) {
			value[i] = (((src[offset + 4 * i] & 0xFF) << 24) | ((src[offset + 1 + 4 * i] & 0xFF) << 16)
					| ((src[offset + 2 + 4 * i] & 0xFF) << 8) | ((src[offset + 3 + 4 * i] & 0xFF) << 0));

		}
		return value;

	}

	public static byte[] intsToBytes(int[] value) {
		byte[] dst = new byte[16];
		for (int i = 0; i < 4; i++) {
			dst[4 * i + 0] = (byte) ((value[i] >> 24) & 0xFF);
			dst[4 * i + 1] = (byte) ((value[i] >> 16) & 0xFF);
			dst[4 * i + 2] = (byte) ((value[i] >> 8) & 0xFF);
			dst[4 * i + 3] = (byte) ((value[i] >> 0) & 0xFF);

		}
		return dst;

	}

	@Override
	protected void onError(byte[] lastRaw, ProtocolException pex) {
		// Protocol error occurred
		// Glitch successful
		verdict(SUCCESSFUL);

		// Unless ATR part of return message
		if (contains(lastRaw, ATR)) {
			// Then assume glitch was detected
			verdict(INCONCLUSIVE);
		}
	}

	/**
	 * If the user checked the "configure card" option the detailed
	 * configuration options are pushed to the target.
	 * 
	 * @throws IOException
	 *             if something went wrong during card communication
	 */

	public static class Contactless_ProtocolSettings {

		public static enum Mode {
			ExternalAuth, InternalAuth, SM2GenKeyPair;
		}

		@DisplayName("Command")
		@ShortDescription("Select Test Command")
		private Mode mode = Mode.InternalAuth;

		public Mode getMode() {
			return mode;
		}

		public void setMode(Mode mode) {
			Mode old = this.mode;
			this.mode = mode;
			pcs.firePropertyChange("mode", old, this.mode);
		}

		/*
		 * Property change support
		 */
		protected PropertyChangeSupport pcs = new PropertyChangeSupport(this);

		public void addPropertyChangeListener(PropertyChangeListener listener) {
			this.pcs.addPropertyChangeListener(listener);
		}

		public void addPropertyChangeListener(String propertyName, PropertyChangeListener listener) {
			this.pcs.addPropertyChangeListener(propertyName, listener);
		}

		public void removePropertyChangeListener(PropertyChangeListener listener) {
			this.pcs.removePropertyChangeListener(listener);
		}

		public void removePropertyChangeListener(String propertyName, PropertyChangeListener listener) {
			this.pcs.removePropertyChangeListener(propertyName, listener);
		}

		public static void main(String[] args) {
			byte[] response;
			response = hex("C59B802A354579689000");
			byte[] CRandom = sub(response, 0, response.length - STATUS_WORD_LENGTH);
			byte[] TRandom = hex("215b02f346ff130e");
			byte[] SessionKey = SM4EncryptECB(hex(mcck), rightExtend(CRandom, 16));
			byte[] tmpdata = SM4EncryptECB(SessionKey, rightExtend(TRandom, 16));
			byte[] sdata00 = new byte[8];
			for (int i = 0; i < 8; i++) {
				sdata00[i] = (byte) (tmpdata[i] ^ tmpdata[i + 8]);
				System.out.format("%x ", sdata00[i]);
			}
		}
	}

}
