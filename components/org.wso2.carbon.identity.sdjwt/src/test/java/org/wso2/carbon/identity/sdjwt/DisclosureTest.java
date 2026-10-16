/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.sdjwt.constant.SDJWTConstants;
import org.wso2.carbon.identity.sdjwt.exception.SDJWTException;
import org.wso2.carbon.identity.sdjwt.util.SDJWTUtil;

import java.util.Map;

/**
 * Test class for Disclosure.
 * Tests disclosure creation, encoding, parsing, and digest computation.
 */
public class DisclosureTest {

    private static final String TEST_CLAIM_NAME = "email";
    private static final String TEST_CLAIM_VALUE = "user@example.com";
    private static final String TEST_SALT = "test-salt-123456";

    @Test(priority = 1, description = "Test creating and encoding object property disclosure")
    public void testCreateAndEncodeObjectPropertyDisclosure() throws SDJWTException {
        // Create disclosure
        Disclosure disclosure = new Disclosure(TEST_SALT, TEST_CLAIM_NAME, TEST_CLAIM_VALUE);

        // Verify properties
        Assert.assertEquals(disclosure.getSalt(), TEST_SALT);
        Assert.assertEquals(disclosure.getClaimName(), TEST_CLAIM_NAME);
        Assert.assertEquals(disclosure.getClaimValue(), TEST_CLAIM_VALUE);
        Assert.assertFalse(disclosure.isArrayElement());

        // Verify encoding format: [salt, claimName, claimValue]
        String encoded = disclosure.getDisclosure();
        String json = SDJWTUtil.base64UrlDecodeToString(encoded);
        JsonArray array = JsonParser.parseString(json).getAsJsonArray();

        Assert.assertEquals(array.size(), 3);
        Assert.assertEquals(array.get(0).getAsString(), TEST_SALT);
        Assert.assertEquals(array.get(1).getAsString(), TEST_CLAIM_NAME);
        Assert.assertEquals(array.get(2).getAsString(), TEST_CLAIM_VALUE);
    }

    @Test(priority = 2, description = "Test creating and encoding array element disclosure")
    public void testCreateAndEncodeArrayElementDisclosure() throws SDJWTException {
        // Create array element disclosure
        Disclosure disclosure = new Disclosure(TEST_SALT, null, TEST_CLAIM_VALUE);

        // Verify properties
        Assert.assertNull(disclosure.getClaimName());
        Assert.assertTrue(disclosure.isArrayElement());

        // Verify encoding format: [salt, claimValue]
        String encoded = disclosure.getDisclosure();
        String json = SDJWTUtil.base64UrlDecodeToString(encoded);
        JsonArray array = JsonParser.parseString(json).getAsJsonArray();

        Assert.assertEquals(array.size(), 2);
        Assert.assertEquals(array.get(0).getAsString(), TEST_SALT);
        Assert.assertEquals(array.get(1).getAsString(), TEST_CLAIM_VALUE);
    }

    @Test(priority = 3, description = "Test disclosure digest computation")
    public void testDisclosureDigest() throws SDJWTException {
        Disclosure disclosure = new Disclosure(TEST_SALT, TEST_CLAIM_NAME, TEST_CLAIM_VALUE);

        String digest = disclosure.digest();

        Assert.assertNotNull(digest);
        // Verify base64url without padding
        Assert.assertFalse(digest.contains("="));
        Assert.assertFalse(digest.contains("+"));
        Assert.assertFalse(digest.contains("/"));
    }

    @Test(priority = 4, description = "Test array element placeholder creation")
    public void testToArrayElement() throws SDJWTException {
        Disclosure disclosure = new Disclosure(TEST_SALT, null, TEST_CLAIM_VALUE);

        Map<String, Object> placeholder = disclosure.toArrayElement();

        Assert.assertEquals(placeholder.size(), 1);
        Assert.assertTrue(placeholder.containsKey(SDJWTConstants.ARRAY_ELEMENT_KEY));
    }

    @Test(priority = 5, description = "Test round-trip parsing")
    public void testRoundTripParsing() throws SDJWTException {
        // Create original disclosure
        Disclosure original = new Disclosure(TEST_SALT, TEST_CLAIM_NAME, TEST_CLAIM_VALUE);
        String encoded = original.getDisclosure();

        // Parse it back
        Disclosure parsed = Disclosure.parse(encoded);

        // Verify it matches
        Assert.assertEquals(parsed.getSalt(), TEST_SALT);
        Assert.assertEquals(parsed.getClaimName(), TEST_CLAIM_NAME);
        Assert.assertEquals(parsed.getClaimValue(), TEST_CLAIM_VALUE);
        Assert.assertEquals(parsed.getDisclosure(), encoded,
                "A parsed disclosure must return the exact string it was parsed from, not a re-encoding");
    }

    @Test(priority = 6, description = "Test parsing invalid disclosure",
            expectedExceptions = SDJWTException.class)
    public void testParseInvalidDisclosure() throws SDJWTException {
        Disclosure.parse("not-valid-base64-@#$%");
    }

    @Test(priority = 7, description = "Test creating disclosure with null salt",
            expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = ".*Salt cannot be null or empty.*")
    public void testCreateDisclosureWithNullSalt() {
        new Disclosure(null, TEST_CLAIM_NAME, TEST_CLAIM_VALUE);
    }
}

