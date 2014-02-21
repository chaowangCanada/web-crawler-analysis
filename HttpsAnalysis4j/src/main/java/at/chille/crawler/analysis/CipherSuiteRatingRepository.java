package at.chille.crawler.analysis;

import java.util.HashMap;
import java.util.Map;

public class CipherSuiteRatingRepository {

	private float handshakeFactor;
	private float cipherFactor;
	private float hashFactor;
	private Map<String, Rating> handshakeRating;
	private Map<String, Rating> cipherRating;
	private Map<String, Rating> hashRating;
	
	public CipherSuiteRatingRepository() {
		handshakeRating = new HashMap<String, Rating>();
		cipherRating = new HashMap<String, Rating>();
		hashRating = new HashMap<String, Rating>();
	}

	public float getHandshakeFactor() {
		return handshakeFactor;
	}

	public void setHandshakeFactor(float handshakeFactor) {
		this.handshakeFactor = handshakeFactor;
	}

	public float getCipherFactor() {
		return cipherFactor;
	}

	public void setCipherFactor(float cipherFactor) {
		this.cipherFactor = cipherFactor;
	}

	public float getHashFactor() {
		return hashFactor;
	}

	public void setHashFactor(float hashFactor) {
		this.hashFactor = hashFactor;
	}

	public Map<String, Rating> getHandshakeRating() {
		return handshakeRating;
	}

	public void addHandshakeRating(String handshake, Rating rating) {
		this.handshakeRating.put(handshake, rating);
	}

	public Map<String, Rating> getCipherRating() {
		return cipherRating;
	}

	public void addCipherRating(String cipher, Rating rating) {
		this.cipherRating.put(cipher, rating);
	}

	public Map<String, Rating> getHashRating() {
		return hashRating;
	}

	public void addHashRating(String hash, Rating rating) {
		this.hashRating.put(hash, rating);
	}
}
