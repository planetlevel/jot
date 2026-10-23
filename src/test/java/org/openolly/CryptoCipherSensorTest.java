package org.openolly;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openolly.config.ConfigReader;
import org.openolly.reporting.Event;
import org.openolly.reporting.EventBus;
import org.openolly.reporting.EventSink;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

/**
 * The crypto-cipher sensor of the ticketbook demo, which sees a cipher being initialized and says what it is, what it does and what key it
 * was given, all from one call of Cipher.init. It is read out of the demo's own jot file and run on real ciphers and keys from the JDK.
 * It used to be two sensors on the same method, which made two events for every call.
 */
class CryptoCipherSensorTest {

	static final String SOURCE = "demo/ticketbook/.jot/jot.yaml";
	static final String TESTED = "cipher-test-crypto-cipher";
	static Sensor sensor;
	static List<String> problems;
	static List<String> sensorNames = new ArrayList<String>();

	@BeforeAll
	static void loadTheSavedSensor() throws Exception {
		ObjectMapper mapper = new ObjectMapper( new YAMLFactory() );
		JsonNode all = mapper.readTree( new File( SOURCE ) );
		JsonNode saved = null;
		for ( JsonNode candidate : all.get( "sensors" ) ) {
			sensorNames.add( candidate.get( "name" ).asText() );
			if ( "crypto-cipher".equals( candidate.get( "name" ).asText() ) ) saved = candidate;
		}
		Assertions.assertNotNull( saved, "crypto-cipher is not in " + SOURCE );
		// loaded under a name of its own. The sensors of every test share one registry, where the first definition of a name wins, so a
		// file loaded earlier by another test that also defines crypto-cipher would otherwise be the one that is tested
		ObjectNode copy = saved.deepCopy();
		copy.put( "name", TESTED );
		Path only = Files.createTempDirectory( "cipher" ).resolve( "cipher-only.jot" );
		Files.writeString( only, mapper.writeValueAsString( Map.of( "sensors", List.of( copy ) ) ) );
		ConfigReader.load( only.toFile() );
		problems = new ArrayList<String>( ConfigReader.getProblems().stream().filter( p -> p.contains( only.getFileName().toString() ) ).toList() );
		sensor = Sensor.getSensors().stream().filter( s -> TESTED.equals( s.getName() ) ).findFirst().orElse( null );
		AppScope.configure( List.of() );
		PlatformWork.configure( null );
	}

	@AfterAll
	static void noApplicationScopeLeftBehind() {
		AppScope.configure( List.of() );
		PlatformWork.configure( null );
	}

	@BeforeEach
	void noScope() {
		AppScope.configure( List.of() );
	}

	@AfterEach
	void stopTheBus() {
		EventBus.shutdown();
	}

	/** What the sensor records when this cipher is initialized with these arguments, which is how Cipher.init passes them. */
	private List<Event> init(Cipher cipher, Object... arguments) {
		List<Event> out = new ArrayList<Event>();
		EventBus.configure( List.of( (EventSink) out::add ), 100 );
		sensor.execute( "t", "sig", cipher, arguments, null );
		EventBus.shutdown();
		return out;
	}

	private Map<String, Object> only(List<Event> events) {
		Assertions.assertEquals( 1, events.size(), "one call of init is one event" );
		return events.get( 0 ).getData();
	}

	private static Key aesKey(int bits) throws Exception {
		KeyGenerator generator = KeyGenerator.getInstance( "AES" );
		generator.init( bits );
		return generator.generateKey();
	}

	// ------------------------------------------------------------------ the sensor as saved

	@Test
	void itLoadsWithoutProblemsAndWatchesOnlyCipherInit() {
		Assertions.assertNotNull( sensor );
		Assertions.assertTrue( problems.isEmpty(), "the agent found problems with it, " + problems );
		Assertions.assertEquals( List.of( "javax.crypto.Cipher.init" ), sensor.getMethods().stream().map( Object::toString ).map( m -> m.replaceAll( "\\(.*", "" ) ).toList() );
		Assertions.assertNull( sensor.getBlockWhen(), "it only records" );
	}

	@Test
	void itRecordsTheCipherWhatItDoesAndTheKeyInOneEvent() {
		Assertions.assertEquals( List.of( "algorithm", "operation", "key_algorithm", "bits" ), new ArrayList<String>( sensor.getCaptures().keySet() ) );
	}

	@Test
	void theKeySizeSensorIsGoneBecauseThisOneCoversIt() {
		Assertions.assertFalse( sensorNames.contains( "crypto-cipher-key-size" ), "it watched the same method, and made a second event for every call" );
		Assertions.assertEquals( 1, sensorNames.stream().filter( n -> n.equals( "crypto-cipher" ) ).count() );
	}

	// ------------------------------------------------------------------ what it records

	@Test
	void aSymmetricCipherIsRecordedWithItsModeAndTheSizeOfItsKey() throws Exception {
		Cipher cipher = Cipher.getInstance( "AES/CBC/PKCS5Padding" );
		Map<String, Object> data = only( init( cipher, Cipher.ENCRYPT_MODE, aesKey( 128 ) ) );
		Assertions.assertEquals( "AES/CBC/PKCS5Padding", data.get( "algorithm" ), "the cipher's own algorithm, which is what reports of crypto-cipher.algorithm have always shown" );
		Assertions.assertEquals( "encrypt", data.get( "operation" ) );
		Assertions.assertEquals( "AES", data.get( "key_algorithm" ), "the key's algorithm is a field of its own, so it doesn't replace the cipher's" );
		Assertions.assertEquals( 128, data.get( "bits" ), "a number, so it can be compared and sorted" );
	}

	@Test
	void theSizeOfEachKeyIsItsOwn() throws Exception {
		Cipher cipher = Cipher.getInstance( "AES/ECB/PKCS5Padding" );
		for ( int bits : new int[] { 128, 192, 256 } ) {
			try {
				Assertions.assertEquals( bits, only( init( cipher, Cipher.DECRYPT_MODE, aesKey( bits ) ) ).get( "bits" ), bits + " bit key" );
			} catch ( InvalidKeyException unsupported ) {
				// a JDK limited to shorter keys has none of this size to test with
			}
		}
	}

	@Test
	void theModeIsEncryptDecryptOrOther() throws Exception {
		Cipher cipher = Cipher.getInstance( "AES/ECB/PKCS5Padding" );
		Key key = aesKey( 128 );
		Assertions.assertEquals( "encrypt", only( init( cipher, Cipher.ENCRYPT_MODE, key ) ).get( "operation" ) );
		Assertions.assertEquals( "decrypt", only( init( cipher, Cipher.DECRYPT_MODE, key ) ).get( "operation" ) );
		Assertions.assertEquals( "other", only( init( cipher, Cipher.WRAP_MODE, key ) ).get( "operation" ), "wrap" );
		Assertions.assertEquals( "other", only( init( cipher, Cipher.UNWRAP_MODE, key ) ).get( "operation" ), "unwrap" );
	}

	@Test
	void anRsaKeyIsMeasuredByItsModulus() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance( "RSA" );
		generator.initialize( 2048 );
		PublicKey key = generator.generateKeyPair().getPublic();
		Cipher cipher = Cipher.getInstance( "RSA/ECB/PKCS1Padding" );
		Map<String, Object> data = only( init( cipher, Cipher.ENCRYPT_MODE, key ) );
		Assertions.assertEquals( "RSA/ECB/PKCS1Padding", data.get( "algorithm" ) );
		Assertions.assertEquals( "RSA", data.get( "key_algorithm" ) );
		Assertions.assertEquals( 2048, data.get( "bits" ), "the length of the modulus, not the length of the encoded key, which is more" );
	}

	@Test
	void theOtherWaysOfCallingInitAreRecordedTheSame() throws Exception {
		Cipher cipher = Cipher.getInstance( "AES/CBC/PKCS5Padding" );
		Key key = aesKey( 128 );
		for ( Object[] arguments : new Object[][] {
			{ Cipher.ENCRYPT_MODE, key },
			{ Cipher.ENCRYPT_MODE, key, new java.security.SecureRandom() },
			{ Cipher.ENCRYPT_MODE, key, new javax.crypto.spec.IvParameterSpec( new byte[16] ) },
			{ Cipher.ENCRYPT_MODE, key, new javax.crypto.spec.IvParameterSpec( new byte[16] ), new java.security.SecureRandom() } } ) {
			Map<String, Object> data = only( init( cipher, arguments ) );
			Assertions.assertEquals( 128, data.get( "bits" ), arguments.length + " arguments" );
			Assertions.assertEquals( "encrypt", data.get( "operation" ) );
		}
	}

	// ------------------------------------------------------------------ what it can't know

	@Test
	void initWithACertificateIsStillRecordedWithTheCipherAndNoKey() throws Exception {
		Certificate certificate = new Certificate( "X.509" ) {
			public byte[] getEncoded() {
				return new byte[0];
			}

			public void verify(PublicKey key) throws SignatureException {
			}

			public void verify(PublicKey key, String provider) throws SignatureException {
			}

			public String toString() {
				return "a certificate";
			}

			public PublicKey getPublicKey() {
				return null;
			}
		};
		Map<String, Object> data = only( init( Cipher.getInstance( "RSA/ECB/PKCS1Padding" ), Cipher.ENCRYPT_MODE, certificate ) );
		Assertions.assertEquals( "RSA/ECB/PKCS1Padding", data.get( "algorithm" ) );
		Assertions.assertEquals( "encrypt", data.get( "operation" ) );
		Assertions.assertNull( data.get( "key_algorithm" ), "a certificate has no algorithm of its own to give, which is a field with no value and not a lost event" );
		Assertions.assertNull( data.get( "bits" ) );
	}

	@Test
	void aKeyThatWillNotGiveItsBytesIsStillRecordedWithoutItsSize() throws Exception {
		Key locked = new Key() {
			private static final long serialVersionUID = 1L;

			public String getAlgorithm() {
				return "AES";
			}

			public String getFormat() {
				return null;
			}

			public byte[] getEncoded() {
				return null;       // what a key held in hardware gives
			}
		};
		Map<String, Object> data = only( init( Cipher.getInstance( "AES/CBC/PKCS5Padding" ), Cipher.ENCRYPT_MODE, locked ) );
		Assertions.assertEquals( "AES", data.get( "key_algorithm" ), "what the key will say is kept" );
		Assertions.assertNull( data.get( "bits" ), "and what it won't is empty" );
		Assertions.assertEquals( "AES/CBC/PKCS5Padding", data.get( "algorithm" ), "and the cipher is recorded as ever" );
	}

	// ------------------------------------------------------------------ what it must not say

	@Test
	void theKeyItselfIsNeverRecorded() throws Exception {
		Key key = aesKey( 256 );
		Event event = init( Cipher.getInstance( "AES/CBC/PKCS5Padding" ), Cipher.ENCRYPT_MODE, key ).get( 0 );
		String everything = event.getCapture() + " " + event.getData() + " " + event;
		String hex = java.util.HexFormat.of().formatHex( key.getEncoded() );
		String base64 = java.util.Base64.getEncoder().encodeToString( key.getEncoded() );
		Assertions.assertFalse( everything.contains( hex ) || everything.contains( base64 ) || everything.contains( java.util.Arrays.toString( key.getEncoded() ) ), "key material in " + everything );
		for ( Object value : event.getData().values() ) {
			Assertions.assertTrue( value == null || value instanceof String || value instanceof Number, "only text and numbers, " + value );
		}
	}

	@Test
	void everyCallIsOneEventAndNotTwo() throws Exception {
		Cipher cipher = Cipher.getInstance( "AES/ECB/PKCS5Padding" );
		Key key = aesKey( 128 );
		for ( int i = 0; i < 5; i++ ) Assertions.assertEquals( 1, init( cipher, Cipher.ENCRYPT_MODE, key ).size() );
	}
}
