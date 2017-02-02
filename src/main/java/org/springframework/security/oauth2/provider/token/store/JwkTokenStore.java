/*
 * Copyright 2012-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.token.store;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.codec.Codecs;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * @author Joe Grandja
 */
public class JwkTokenStore implements TokenStore {
	private static final String KEY_ID_ATTRIBUTE = "kid";
	private static final String ALGORITHM_ATTRIBUTE = "alg";
	private final JwtTokenStore delegate;

	public JwkTokenStore(String jwkSetUrl) {
		Assert.hasText(jwkSetUrl, "jwkSetUrl cannot be empty");
		JwkDefinitionSource jwkDefinitionSource = new JwkDefinitionSource(jwkSetUrl);
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(jwkDefinitionSource);
		this.delegate = new JwtTokenStore(accessTokenConverter);
	}

	@Override
	public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
		return this.delegate.readAuthentication(token);
	}

	@Override
	public OAuth2Authentication readAuthentication(String token) {
		return this.delegate.readAuthentication(token);
	}

	@Override
	public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		this.delegate.storeAccessToken(token, authentication);
	}

	@Override
	public OAuth2AccessToken readAccessToken(String tokenValue) {
		return this.delegate.readAccessToken(tokenValue);
	}

	@Override
	public void removeAccessToken(OAuth2AccessToken token) {
		this.delegate.removeAccessToken(token);
	}

	@Override
	public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
		this.delegate.storeRefreshToken(refreshToken, authentication);
	}

	@Override
	public OAuth2RefreshToken readRefreshToken(String tokenValue) {
		return this.delegate.readRefreshToken(tokenValue);
	}

	@Override
	public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
		return this.delegate.readAuthenticationForRefreshToken(token);
	}

	@Override
	public void removeRefreshToken(OAuth2RefreshToken token) {
		this.delegate.removeRefreshToken(token);
	}

	@Override
	public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
		this.delegate.removeAccessTokenUsingRefreshToken(refreshToken);
	}

	@Override
	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
		return this.delegate.getAccessToken(authentication);
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
		return this.delegate.findTokensByClientIdAndUserName(clientId, userName);
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
		return this.delegate.findTokensByClientId(clientId);
	}

	private static class JwkVerifyingJwtAccessTokenConverter extends JwtAccessTokenConverter {
		private final JwkDefinitionSource jwkDefinitionSource;
		private final org.springframework.security.oauth2.common.util.JsonParser jsonParser;

		private JwkVerifyingJwtAccessTokenConverter(JwkDefinitionSource jwkDefinitionSource) {
			this.jwkDefinitionSource = jwkDefinitionSource;
			this.jsonParser = JsonParserFactory.create();
		}

		@Override
		protected Map<String, Object> decode(String token) {
			try {
				Map<String, String> headers = JwtParser.parseHeaders(token);

				// Validate "kid" header
				String keyIdHeader = headers.get(KEY_ID_ATTRIBUTE);
				if (keyIdHeader == null) {
					throw new JwkException("Invalid JWT/JWS: \"" + KEY_ID_ATTRIBUTE + "\" is a required JOSE Header.");
				}
				JwkDefinition jwkDefinition = this.jwkDefinitionSource.getDefinitionRefreshIfNecessary(keyIdHeader);
				if (jwkDefinition == null) {
					throw new JwkException("Invalid JOSE Header \"" + KEY_ID_ATTRIBUTE + "\" (" + keyIdHeader + ")");
				}

				// Validate "alg" header
				String algorithmHeader = headers.get(ALGORITHM_ATTRIBUTE);
				if (algorithmHeader == null) {
					throw new JwkException("Invalid JWT/JWS: \"" + ALGORITHM_ATTRIBUTE + "\" is a required JOSE Header.");
				}
				if (!algorithmHeader.equals(jwkDefinition.getAlgorithm().headerParamValue())) {
					throw new JwkException("Invalid JOSE Header \"" + ALGORITHM_ATTRIBUTE + "\" (" + algorithmHeader + ")" +
							" does not match algorithm associated with \"" + KEY_ID_ATTRIBUTE + "\" (" + keyIdHeader + ")");
				}

				// Verify signature
				SignatureVerifier verifier = this.jwkDefinitionSource.getVerifier(keyIdHeader);
				Jwt jwt = JwtHelper.decode(token);
				jwt.verifySignature(verifier);

				Map<String, Object> claims = this.jsonParser.parseMap(jwt.getClaims());
				if (claims.containsKey(EXP) && claims.get(EXP) instanceof Integer) {
					Integer expiryInt = (Integer) claims.get(EXP);
					claims.put(EXP, new Long(expiryInt));
				}

				return claims;

			} catch (Exception ex) {
				throw new InvalidTokenException("Failed to convert JWT/JWS: " + ex.getMessage(), ex);
			}
		}

		@Override
		protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
			throw new UnsupportedOperationException("JWT/JWS (signing) is currently not supported.");
		}
	}

	private static class JwkDefinitionSource {
		private final URL jwkSetUrl;
		private final AtomicReference<Map<JwkDefinition, SignatureVerifier>> jwkDefinitions = new AtomicReference<>(new HashMap<>());

		private JwkDefinitionSource(String jwkSetUrl) {
			try {
				this.jwkSetUrl = new URL(jwkSetUrl);
			} catch (MalformedURLException ex) {
				throw new IllegalArgumentException("Invalid JWK Set URL: " + ex.getMessage(), ex);
			}
		}

		private JwkDefinition getDefinition(String keyId) {
			JwkDefinition result = null;
			for (JwkDefinition jwkDefinition : this.jwkDefinitions.get().keySet()) {
				if (jwkDefinition.getKeyId().equals(keyId)) {
					result = jwkDefinition;
					break;
				}
			}
			return result;
		}

		private JwkDefinition getDefinitionRefreshIfNecessary(String keyId) {
			JwkDefinition result = this.getDefinition(keyId);
			if (result != null) {
				return result;
			}
			this.refreshJwkDefinitions();
			return this.getDefinition(keyId);
		}

		private SignatureVerifier getVerifier(String keyId) {
			SignatureVerifier result = null;
			JwkDefinition jwkDefinition = this.getDefinitionRefreshIfNecessary(keyId);
			if (jwkDefinition != null) {
				result = this.jwkDefinitions.get().get(jwkDefinition);
			}
			return result;
		}

		private void refreshJwkDefinitions() {
			Set<JwkDefinition> jwkDefinitionSet;
			try {
				jwkDefinitionSet = JwkSetParser.parse(this.jwkSetUrl);
			} catch (IOException ex) {
				throw new JwkException("An I/O error occurred while refreshing the JWK Set: " + ex.getMessage(), ex);
			}

			Map<JwkDefinition, SignatureVerifier> refreshedJwkDefinitions = new HashMap<>();

			for (JwkDefinition jwkDefinition : jwkDefinitionSet) {
				if (JwkDefinition.KeyType.RSA.equals(jwkDefinition.getKeyType())) {
					refreshedJwkDefinitions.put(jwkDefinition, this.createRSAVerifier((RSAJwkDefinition)jwkDefinition));
				}
			}

			this.jwkDefinitions.set(refreshedJwkDefinitions);
		}

		private RsaVerifier createRSAVerifier(RSAJwkDefinition rsaDefinition) {
			RsaVerifier result;
			try {
				BigInteger modulus = new BigInteger(Codecs.b64UrlDecode(rsaDefinition.getModulus()));
				BigInteger exponent = new BigInteger(Codecs.b64UrlDecode(rsaDefinition.getExponent()));

				RSAPublicKey rsaPublicKey = (RSAPublicKey)KeyFactory.getInstance("RSA")
						.generatePublic(new RSAPublicKeySpec(modulus, exponent));

				result = new RsaVerifier(rsaPublicKey, rsaDefinition.getAlgorithm().standardName());

			} catch (Exception ex) {
				throw new JwkException("An error occurred while creating a RSA Public Key Verifier for \"" +
						rsaDefinition.getKeyId() + "\" : " + ex.getMessage(), ex);
			}
			return result;
		}
	}

	private static class JwtParser {
		private static final JsonFactory factory = new JsonFactory();

		private static Map<String, String> parseHeaders(String token) throws IOException {
			Map<String, String> headers;

			int headerEndIndex = token.indexOf('.');
			if (headerEndIndex == -1) {
				throw new IllegalArgumentException("Invalid JWT. Missing JOSE Header.");
			}
			byte[] decodedHeader = Codecs.b64UrlDecode(token.substring(0, headerEndIndex));

			JsonParser parser = factory.createParser(decodedHeader);
			try {
				headers = new HashMap<>();
				if (parser.nextToken() == JsonToken.START_OBJECT) {
					while (parser.nextToken() == JsonToken.FIELD_NAME) {
						String headerName = parser.getCurrentName();
						parser.nextToken();
						String headerValue = parser.getValueAsString();
						headers.put(headerName, headerValue);
					}
				}

			} finally {
				try {
					parser.close();
				} catch (IOException ex) { }
			}

			return headers;
		}
	}

	private static class JwkSetParser {
		private static final String KEY_TYPE_ATTRIBUTE = "kty";
		private static final String PUBLIC_KEY_USE_ATTRIBUTE = "use";
		private static final String RSA_PUBLIC_KEY_MODULUS_ATTRIBUTE = "n";
		private static final String RSA_PUBLIC_KEY_EXPONENT_ATTRIBUTE = "e";
		private static final String KEYS_ATTRIBUTE = "keys";
		private static final JsonFactory factory = new JsonFactory();

		private static Set<JwkDefinition> parse(URL jwkSetUrl) throws IOException {
			Set<JwkDefinition> jwkDefinitions;

			JsonParser parser = factory.createParser(jwkSetUrl);
			try {
				if (parser.nextToken() != JsonToken.START_OBJECT) {
					throw new JwkException("Invalid JWK Set Object.");
				}
				if (parser.nextToken() != JsonToken.FIELD_NAME) {
					throw new JwkException("Invalid JWK Set Object.");
				}
				if (!parser.getCurrentName().equals(KEYS_ATTRIBUTE)) {
					throw new JwkException("Invalid JWK Set Object. The JWK Set MUST have a \"" + KEYS_ATTRIBUTE + "\" attribute.");
				}
				if (parser.nextToken() != JsonToken.START_ARRAY) {
					throw new JwkException("Invalid JWK Set Object. The JWK Set MUST have at least one JWK.");
				}

				jwkDefinitions = new LinkedHashSet<>();
				Map<String, String> attributes = new HashMap<>();

				while (parser.nextToken() == JsonToken.START_OBJECT) {
					while (parser.nextToken() == JsonToken.FIELD_NAME) {
						String attributeName = parser.getCurrentName();
						parser.nextToken();
						String attributeValue = parser.getValueAsString();
						attributes.put(attributeName, attributeValue);
					}
					JwkDefinition jwkDefinition = createJwkDefinition(attributes);
					if (!jwkDefinitions.add(jwkDefinition)) {
						throw new JwkException("Duplicate JWK found in Set: " +
								jwkDefinition.getKeyId() + " (" + KEY_ID_ATTRIBUTE + ")");
					}
					attributes.clear();
				}

			} finally {
				try {
					parser.close();
				} catch (IOException ex) { }
			}

			return jwkDefinitions;
		}

		private static JwkDefinition createJwkDefinition(Map<String, String> attributes) {
			JwkDefinition.KeyType keyType =
					JwkDefinition.KeyType.fromValue(attributes.get(KEY_TYPE_ATTRIBUTE));

			if (!JwkDefinition.KeyType.RSA.equals(keyType)) {
				throw new JwkException((keyType != null ? keyType.value() : "unknown") +
						" (" + KEY_TYPE_ATTRIBUTE + ") is currently not supported.");
			}

			return createRSAJwkDefinition(attributes);
		}

		private static JwkDefinition createRSAJwkDefinition(Map<String, String> attributes) {
			// kid
			String keyId = attributes.get(KEY_ID_ATTRIBUTE);
			if (!StringUtils.hasText(keyId)) {
				throw new JwkException("\"" + KEY_ID_ATTRIBUTE + "\" is a required attribute for a JWK.");
			}

			// use
			JwkDefinition.PublicKeyUse publicKeyUse =
					JwkDefinition.PublicKeyUse.fromValue(attributes.get(PUBLIC_KEY_USE_ATTRIBUTE));
			if (!JwkDefinition.PublicKeyUse.SIG.equals(publicKeyUse)) {
				throw new JwkException((publicKeyUse != null ? publicKeyUse.value() : "unknown") +
						" (" + PUBLIC_KEY_USE_ATTRIBUTE + ") is currently not supported.");
			}

			// alg
			JwkDefinition.CryptoAlgorithm algorithm =
					JwkDefinition.CryptoAlgorithm.fromStandardName(attributes.get(ALGORITHM_ATTRIBUTE));
			if (!JwkDefinition.CryptoAlgorithm.RS256.equals(algorithm) &&
					!JwkDefinition.CryptoAlgorithm.RS384.equals(algorithm) &&
					!JwkDefinition.CryptoAlgorithm.RS512.equals(algorithm)) {
				throw new JwkException((algorithm != null ? algorithm.standardName() : "unknown") +
						" (" + ALGORITHM_ATTRIBUTE + ") is currently not supported.");
			}

			// n
			String modulus = attributes.get(RSA_PUBLIC_KEY_MODULUS_ATTRIBUTE);
			if (!StringUtils.hasText(modulus)) {
				throw new JwkException("\"" + RSA_PUBLIC_KEY_MODULUS_ATTRIBUTE + "\" is a required attribute for a RSA JWK.");
			}

			// e
			String exponent = attributes.get(RSA_PUBLIC_KEY_EXPONENT_ATTRIBUTE);
			if (!StringUtils.hasText(exponent)) {
				throw new JwkException("\"" + RSA_PUBLIC_KEY_EXPONENT_ATTRIBUTE + "\" is a required attribute for a RSA JWK.");
			}

			RSAJwkDefinition jwkDefinition = new RSAJwkDefinition(
					keyId, publicKeyUse, algorithm, modulus, exponent);

			return jwkDefinition;
		}
	}

	private abstract static class JwkDefinition {
		private final String keyId;
		private final KeyType keyType;
		private final PublicKeyUse publicKeyUse;
		private final CryptoAlgorithm algorithm;

		protected JwkDefinition(String keyId,
								KeyType keyType,
								PublicKeyUse publicKeyUse,
								CryptoAlgorithm algorithm) {
			this.keyId = keyId;
			this.keyType = keyType;
			this.publicKeyUse = publicKeyUse;
			this.algorithm = algorithm;
		}

		protected String getKeyId() {
			return this.keyId;
		}

		protected KeyType getKeyType() {
			return this.keyType;
		}

		protected PublicKeyUse getPublicKeyUse() {
			return this.publicKeyUse;
		}

		protected CryptoAlgorithm getAlgorithm() {
			return this.algorithm;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null || this.getClass() != obj.getClass()) {
				return false;
			}

			JwkDefinition that = (JwkDefinition) obj;
			if (!this.getKeyId().equals(that.getKeyId())) {
				return false;
			}

			return this.getKeyType().equals(that.getKeyType());
		}

		@Override
		public int hashCode() {
			int result = this.getKeyId().hashCode();
			result = 31 * result + this.getKeyType().hashCode();
			return result;
		}

		enum KeyType {
			RSA("RSA"),
			EC("EC"),
			OCT("oct");

			private final String value;

			KeyType(String value) {
				this.value = value;
			}

			private String value() {
				return this.value;
			}

			private static KeyType fromValue(String value) {
				KeyType result = null;
				for (KeyType keyType : values()) {
					if (keyType.value().equals(value)) {
						result = keyType;
						break;
					}
				}
				return result;
			}
		}

		enum PublicKeyUse {
			SIG("sig"),
			ENC("enc");

			private final String value;

			PublicKeyUse(String value) {
				this.value = value;
			}

			private String value() {
				return this.value;
			}

			private static PublicKeyUse fromValue(String value) {
				PublicKeyUse result = null;
				for (PublicKeyUse publicKeyUse : values()) {
					if (publicKeyUse.value().equals(value)) {
						result = publicKeyUse;
						break;
					}
				}
				return result;
			}
		}

		enum CryptoAlgorithm {
			RS256("SHA256withRSA", "RS256", "RSASSA-PKCS1-v1_5 using SHA-256"),
			RS384("SHA384withRSA", "RS384", "RSASSA-PKCS1-v1_5 using SHA-384"),
			RS512("SHA512withRSA", "RS512", "RSASSA-PKCS1-v1_5 using SHA-512");

			private final String standardName;		// JCA Standard Name
			private final String headerParamValue;
			private final String description;

			CryptoAlgorithm(String standardName, String headerParamValue, String description) {
				this.standardName = standardName;
				this.headerParamValue = headerParamValue;
				this.description = description;
			}

			private String standardName() {
				return this.standardName;
			}

			private String headerParamValue() {
				return this.headerParamValue;
			}

			private String description() {
				return this.description;
			}

			private static CryptoAlgorithm fromStandardName(String standardName) {
				CryptoAlgorithm result = null;
				for (CryptoAlgorithm algorithm : values()) {
					if (algorithm.standardName().equals(standardName)) {
						result = algorithm;
						break;
					}
				}
				return result;
			}
		}
	}

	private static class RSAJwkDefinition extends JwkDefinition {
		private final String modulus;
		private final String exponent;

		private RSAJwkDefinition(String keyId,
								 PublicKeyUse publicKeyUse,
								 CryptoAlgorithm algorithm,
								 String modulus,
								 String exponent) {

			super(keyId, KeyType.RSA, publicKeyUse, algorithm);
			this.modulus = modulus;
			this.exponent = exponent;
		}

		private String getModulus() {
			return this.modulus;
		}

		private String getExponent() {
			return this.exponent;
		}
	}
}