package com.acme.ticketbook.idor;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * How each level of the IDOR exercise turns what a request carries into the id its accessor takes, and the reverse, which is how the
 * application hands the id out to its owner. The level says how much the id has been disguised, the channel says where in the request
 * it sits.
 */
final class Carriers {

	static final String[] CHANNELS = { "query", "form", "path", "header", "cookie", "json" };

	/** Which accessor to call (I the numeric id, N the ticket number, R the reference) and the value to give it. */
	static final class Target {
		final char kind;
		final String value;

		Target(char kind, String value) {
			this.kind = kind;
			this.value = value;
		}
	}

	static class BadId extends RuntimeException {
		BadId(String message) {
			super(message);
		}
	}

	private static final Pattern INT = Pattern.compile("\\d{1,6}");
	private static final Pattern NUMBER = Pattern.compile("\\d{8}");
	private static final Pattern REF = Pattern.compile("[A-Za-z]{2}-\\d+");

	/** The id a request carries, as the target to look up. Throws BadId when it isn't an id at all. */
	static Target resolve(int level, String channel, String raw) {
		try {
			if (raw == null || raw.trim().isEmpty()) {
				throw new BadId("No id");
			}
			if (channel.equals("json") && level < 3) {
				raw = field(raw, "id");
			}
			switch (level) {
			case 1:
				return shape(raw);
			case 2:
				return derived(channel, raw);
			case 3:
				return wrapped(channel, raw);
			default:
				throw new BadId("No such level");
			}
		} catch (BadId e) {
			throw e;
		} catch (RuntimeException e) {
			throw new BadId("That is not an id");
		}
	}

	/** Level 1, the id as it is, and its shape picks the accessor. */
	private static Target shape(String raw) {
		raw = raw.trim();
		if (INT.matcher(raw).matches()) return new Target('I', raw);
		if (NUMBER.matcher(raw).matches()) return new Target('N', raw);
		if (REF.matcher(raw).matches()) return new Target('R', raw);
		throw new BadId("That is not an id");
	}

	/** Level 2, the server reshapes what it was sent, differently in each channel. */
	private static Target derived(String channel, String raw) {
		switch (channel) {
		case "query":                                  // 1001 becomes TB-1001
			return new Target('R', "TB-" + raw);
		case "form":                                   // tk1001 loses its first two characters
			return new Target('I', raw.substring(2));
		case "path": {                                 // 10-01 is the two halves of 1001
			String[] halves = raw.split("-");
			return new Target('I', halves[0] + halves[1]);
		}
		case "header":                                 // the number is the id plus 5000
			return new Target('I', "" + (Integer.parseInt(raw.trim()) - 5000));
		case "cookie":                                 // the digits are backwards
			return new Target('I', new StringBuilder(raw.trim()).reverse().toString());
		default:                                       // json, case and spaces don't matter
			return new Target('R', raw.trim().toUpperCase());
		}
	}

	/** Level 3, the id sits inside a carrier. */
	private static Target wrapped(String channel, String raw) {
		switch (channel) {
		case "query":                                  // base64
			return new Target('I', new String(Base64.getUrlDecoder().decode(raw.trim()), StandardCharsets.UTF_8));
		case "form":                                   // hex
			return new Target('I', fromHex(raw.trim()));
		case "path": {                                 // a JWT whose signature is never checked
			String[] parts = raw.split("\\.");
			return new Target('I', field(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8), "tid"));
		}
		case "header":                                 // base64 of a JSON object
			return new Target('R', field(new String(Base64.getDecoder().decode(raw.trim()), StandardCharsets.UTF_8), "id"));
		case "cookie":                                 // URL encoded JSON, with the id nested
			return new Target('I', field(URLDecoder.decode(raw, StandardCharsets.UTF_8), "id"));
		default:                                       // a JSON body
			return new Target('R', field(raw, "ref"));
		}
	}

	/** What the application gives its owner to send back for this record, the legitimate value of the id in this level and channel. */
	static String encode(int level, String channel, Doc d) {
		switch (level) {
		case 1:
			switch (channel) {
			case "query": case "header": return "" + d.id;
			case "form": case "cookie": return d.number;
			case "path": return d.ref;
			default: return "{\"id\":\"" + d.ref + "\"}";
			}
		case 2:
			switch (channel) {
			case "query": return "" + d.id;
			case "form": return "tk" + d.id;
			case "path": return ("" + d.id).substring(0, 2) + "-" + ("" + d.id).substring(2);
			case "header": return "" + (d.id + 5000);
			case "cookie": return new StringBuilder("" + d.id).reverse().toString();
			default: return "{\"id\":\" " + d.ref.toLowerCase() + " \"}";
			}
		default:
			switch (channel) {
			case "query": return Base64.getUrlEncoder().encodeToString(("" + d.id).getBytes(StandardCharsets.UTF_8));
			case "form": return toHex("" + d.id);
			case "path": return b64url("{\"alg\":\"none\"}") + "." + b64url("{\"tid\":" + d.id + "}") + ".";
			case "header": return Base64.getEncoder().encodeToString(("{\"id\":\"" + d.ref + "\"}").getBytes(StandardCharsets.UTF_8));
			case "cookie": return URLEncoder.encode("{\"ticket\":{\"id\":" + d.id + "}}", StandardCharsets.UTF_8);
			default: return "{\"ticket\":{\"ref\":\"" + d.ref + "\"}}";
			}
		}
	}

	private static String b64url(String s) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
	}

	private static String toHex(String s) {
		StringBuilder sb = new StringBuilder();
		for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

	private static String fromHex(String hex) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i + 1 < hex.length(); i += 2) {
			sb.append((char) Integer.parseInt(hex.substring(i, i + 2), 16));
		}
		return sb.toString();
	}

	/** One value from a JSON text. This is not a parser, the exercise's bodies are flat enough for a pattern. */
	static String field(String json, String name) {
		Matcher m = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*(?:\"([^\"]*)\"|([^,}\\s]+))").matcher(json == null ? "" : json);
		if (!m.find()) {
			return null;
		}
		return m.group(1) != null ? m.group(1) : m.group(2);
	}
}
