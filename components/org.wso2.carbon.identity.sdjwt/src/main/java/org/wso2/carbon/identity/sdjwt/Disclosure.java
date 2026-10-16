/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sdjwt;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import org.wso2.carbon.identity.sdjwt.constant.SDJWTConstants;
import org.wso2.carbon.identity.sdjwt.exception.SDJWTException;
import org.wso2.carbon.identity.sdjwt.util.SDJWTUtil;

import java.util.Map;

/**
 * Represents an SD-JWT Disclosure.
 * <p>
 * A Disclosure for an object property consists of: [salt, claimName, claimValue]
 * A Disclosure for an array element consists of: [salt, claimValue]
 * <p>
 * The Disclosure is base64url-encoded for transmission.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9901.html">RFC 9901 - SD-JWT Specification</a>
 */
public final class Disclosure {

    private static final Gson GSON = new GsonBuilder().serializeNulls().create();

    private final String salt;
    private final String claimName;
    private final Object claimValue;
    private String cachedDisclosure;

    /**
     * Constructor for object property disclosure with auto-generated salt.
     *
     * @param claimName  The claim name
     * @param claimValue The claim value (can be any JSON-compatible type)
     */
    public Disclosure(String claimName, Object claimValue) {

        this(SDJWTUtil.generateSalt(), claimName, claimValue);
    }

    /**
     * Constructor for object property disclosure with explicit salt.
     *
     * @param salt       The salt value (should be base64url-encoded random bytes)
     * @param claimName  The claim name (null for array elements)
     * @param claimValue The claim value (can be any JSON-compatible type)
     */
    public Disclosure(String salt, String claimName, Object claimValue) {

        if (salt == null || salt.isEmpty()) {
            throw new IllegalArgumentException("Salt cannot be null or empty");
        }
        this.salt = salt;
        this.claimName = claimName;
        this.claimValue = claimValue;
    }

    /**
     * Constructor for array element disclosure with auto-generated salt.
     *
     * @param claimValue The array element value
     */
    public Disclosure(Object claimValue) {

        this(SDJWTUtil.generateSalt(), null, claimValue);
    }

    /**
     * Get the base64url-encoded disclosure string.
     * <p>
     * For object properties: base64url([salt, claimName, claimValue])
     * For array elements: base64url([salt, claimValue])
     *
     * @return The base64url-encoded disclosure string
     */
    public String getDisclosure() {

        if (cachedDisclosure == null) {
            cachedDisclosure = computeDisclosure();
        }
        return cachedDisclosure;
    }

    /**
     * Compute the digest of this disclosure using the specified hash algorithm.
     *
     * @param hashAlgorithm The hash algorithm to use (e.g., "sha-256")
     * @return Base64url-encoded digest
     * @throws SDJWTException If hash computation fails
     */
    public String digest(String hashAlgorithm) throws SDJWTException {

        return SDJWTUtil.hashAndEncode(getDisclosure(), hashAlgorithm);
    }

    /**
     * Compute the digest of this disclosure using the default hash algorithm (SHA-256).
     *
     * @return Base64url-encoded digest
     * @throws SDJWTException If hash computation fails
     */
    public String digest() throws SDJWTException {

        return digest(SDJWTConstants.DEFAULT_HASH_ALGORITHM);
    }

    /**
     * Create a Map representing a selectively-disclosable array element placeholder.
     * The map contains a single entry: {"...": "&lt;digest&gt;"}
     *
     * @return Map representing the array element placeholder
     * @throws SDJWTException If digest computation fails
     */
    public Map<String, Object> toArrayElement() throws SDJWTException {

        return toArrayElement(SDJWTConstants.DEFAULT_HASH_ALGORITHM);
    }

    /**
     * Create a Map representing a selectively-disclosable array element placeholder
     * using the specified hash algorithm.
     *
     * @param hashAlgorithm The hash algorithm to use
     * @return Map representing the array element placeholder
     * @throws SDJWTException If digest computation fails
     */
    public Map<String, Object> toArrayElement(String hashAlgorithm) throws SDJWTException {

        return java.util.Collections.singletonMap(SDJWTConstants.ARRAY_ELEMENT_KEY, digest(hashAlgorithm));
    }

    /**
     * Parse a base64url-encoded disclosure string back into a Disclosure object.
     *
     * @param disclosureString The base64url-encoded disclosure string
     * @return Parsed Disclosure object
     * @throws SDJWTException If parsing fails
     */
    public static Disclosure parse(String disclosureString) throws SDJWTException {

        if (disclosureString == null || disclosureString.isEmpty()) {
            throw new SDJWTException("Disclosure string cannot be null or empty");
        }

        try {
            String json = SDJWTUtil.base64UrlDecodeToString(disclosureString);
            JsonElement element = JsonParser.parseString(json);

            if (!element.isJsonArray()) {
                throw new SDJWTException("Disclosure must be a JSON array");
            }

            JsonArray array = element.getAsJsonArray();

            Disclosure disclosure;
            if (array.size() == 2) {
                // Array element disclosure: [salt, value]
                String salt = array.get(0).getAsString();
                Object value = parseJsonElement(array.get(1));
                disclosure = new Disclosure(salt, null, value);
            } else if (array.size() == 3) {
                // Object property disclosure: [salt, claimName, value]
                String salt = array.get(0).getAsString();
                String claimName = array.get(1).getAsString();
                Object value = parseJsonElement(array.get(2));
                disclosure = new Disclosure(salt, claimName, value);
            } else {
                throw new SDJWTException("Disclosure array must have 2 or 3 elements, found: " + array.size());
            }
            // Retain the exact received string so digests are computed over the bytes actually
            // transmitted, not a Gson re-encoding that may differ in formatting/escaping.
            disclosure.cachedDisclosure = disclosureString;
            return disclosure;
        } catch (IllegalArgumentException e) {
            throw new SDJWTException("Invalid base64url encoding in disclosure: " + e.getMessage(), e);
        } catch (JsonSyntaxException e) {
            throw new SDJWTException("Invalid JSON in disclosure: " + e.getMessage(), e);
        } catch (IllegalStateException e) {
            throw new SDJWTException("Invalid disclosure format: " + e.getMessage(), e);
        }
    }

    private String computeDisclosure() {

        JsonArray array = new JsonArray();
        array.add(salt);

        if (claimName != null) {
            // Object property disclosure: [salt, claimName, claimValue]
            array.add(claimName);
        }
        // Add claim value (for both object properties and array elements)
        array.add(GSON.toJsonTree(claimValue));

        String json = GSON.toJson(array);
        return SDJWTUtil.base64UrlEncode(json);
    }

    private static Object parseJsonElement(JsonElement element) {

        if (element.isJsonNull()) {
            return null;
        } else if (element.isJsonPrimitive()) {
            if (element.getAsJsonPrimitive().isBoolean()) {
                return element.getAsBoolean();
            } else if (element.getAsJsonPrimitive().isNumber()) {
                return element.getAsNumber();
            } else {
                return element.getAsString();
            }
        } else {
            // For objects and arrays, return as-is (as JsonElement or convert to Map/List)
            return GSON.fromJson(element, Object.class);
        }
    }

    /**
     * Get the salt value.
     *
     * @return The salt
     */
    public String getSalt() {

        return salt;
    }

    /**
     * Get the claim name.
     *
     * @return The claim name, or null for array element disclosures
     */
    public String getClaimName() {

        return claimName;
    }

    /**
     * Get the claim value.
     *
     * @return The claim value
     */
    public Object getClaimValue() {

        return claimValue;
    }

    /**
     * Check if this is an array element disclosure.
     *
     * @return true if this is an array element disclosure (claimName is null)
     */
    public boolean isArrayElement() {

        return claimName == null;
    }

    @Override
    public String toString() {

        return getDisclosure();
    }
}
