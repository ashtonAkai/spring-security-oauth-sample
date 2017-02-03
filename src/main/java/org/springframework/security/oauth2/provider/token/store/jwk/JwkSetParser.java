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
package org.springframework.security.oauth2.provider.token.store.jwk;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.springframework.security.oauth2.provider.token.store.jwk.JwkAttributes.*;


/**
 * @author Joe Grandja
 */
class JwkSetParser {
	private static final JsonFactory factory = new JsonFactory();

	static Set<JwkDefinition> parse(URL jwkSetUrl) throws IOException {
		Set<JwkDefinition> jwkDefinitions;

		JsonParser parser = factory.createParser(jwkSetUrl);
		try {
			if (parser.nextToken() != JsonToken.START_OBJECT) {
				throw new JwkException("Invalid JWK Set Object.");
			}
			if (parser.nextToken() != JsonToken.FIELD_NAME) {
				throw new JwkException("Invalid JWK Set Object.");
			}
			if (!parser.getCurrentName().equals(KEYS)) {
				throw new JwkException("Invalid JWK Set Object. The JWK Set MUST have a \"" + KEYS + "\" attribute.");
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
							jwkDefinition.getKeyId() + " (" + KEY_ID + ")");
				}
				attributes.clear();
			}

		} finally {
			try {
				parser.close();
			} catch (IOException ex) {
			}
		}

		return jwkDefinitions;
	}

	private static JwkDefinition createJwkDefinition(Map<String, String> attributes) {
		JwkDefinition.KeyType keyType =
				JwkDefinition.KeyType.fromValue(attributes.get(KEY_TYPE));

		if (!JwkDefinition.KeyType.RSA.equals(keyType)) {
			throw new JwkException((keyType != null ? keyType.value() : "unknown") +
					" (" + KEY_TYPE + ") is currently not supported.");
		}

		return createRSAJwkDefinition(attributes);
	}

	private static JwkDefinition createRSAJwkDefinition(Map<String, String> attributes) {
		// kid
		String keyId = attributes.get(KEY_ID);
		if (!StringUtils.hasText(keyId)) {
			throw new JwkException("\"" + KEY_ID + "\" is a required attribute for a JWK.");
		}

		// use
		JwkDefinition.PublicKeyUse publicKeyUse =
				JwkDefinition.PublicKeyUse.fromValue(attributes.get(PUBLIC_KEY_USE));
		if (!JwkDefinition.PublicKeyUse.SIG.equals(publicKeyUse)) {
			throw new JwkException((publicKeyUse != null ? publicKeyUse.value() : "unknown") +
					" (" + PUBLIC_KEY_USE + ") is currently not supported.");
		}

		// alg
		JwkDefinition.CryptoAlgorithm algorithm =
				JwkDefinition.CryptoAlgorithm.fromStandardName(attributes.get(ALGORITHM));
		if (!JwkDefinition.CryptoAlgorithm.RS256.equals(algorithm) &&
				!JwkDefinition.CryptoAlgorithm.RS384.equals(algorithm) &&
				!JwkDefinition.CryptoAlgorithm.RS512.equals(algorithm)) {
			throw new JwkException((algorithm != null ? algorithm.standardName() : "unknown") +
					" (" + ALGORITHM + ") is currently not supported.");
		}

		// n
		String modulus = attributes.get(RSA_PUBLIC_KEY_MODULUS);
		if (!StringUtils.hasText(modulus)) {
			throw new JwkException("\"" + RSA_PUBLIC_KEY_MODULUS + "\" is a required attribute for a RSA JWK.");
		}

		// e
		String exponent = attributes.get(RSA_PUBLIC_KEY_EXPONENT);
		if (!StringUtils.hasText(exponent)) {
			throw new JwkException("\"" + RSA_PUBLIC_KEY_EXPONENT + "\" is a required attribute for a RSA JWK.");
		}

		RSAJwkDefinition jwkDefinition = new RSAJwkDefinition(
				keyId, publicKeyUse, algorithm, modulus, exponent);

		return jwkDefinition;
	}
}