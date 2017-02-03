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
import org.springframework.security.jwt.codec.Codecs;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Joe Grandja
 */
class JwtParser {
	private static final JsonFactory factory = new JsonFactory();

	static Map<String, String> parseHeaders(String token) throws IOException {
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
