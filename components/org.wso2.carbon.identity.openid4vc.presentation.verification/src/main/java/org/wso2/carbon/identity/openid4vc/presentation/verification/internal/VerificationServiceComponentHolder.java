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

package org.wso2.carbon.identity.openid4vc.presentation.verification.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.wso2.carbon.identity.openid4vc.presentation.verification.validators.CredentialSignatureValidator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Stream;

/**
 * Singleton holder for the registered {@link CredentialSignatureValidator} instances.
 *
 * <p>Built-in validators are pre-loaded during bundle activation.
 * External validators arrive through the OSGi {@code @Reference(MULTIPLE, DYNAMIC)} collector
 * in {@link VerificationSignatureValidatorComponent} and are added/removed at runtime.
 *
 * <p>Lookup priority: external validators take precedence over built-ins, allowing deployments
 * to override a built-in type with a custom implementation.
 */
public class VerificationServiceComponentHolder {

    private static final VerificationServiceComponentHolder INSTANCE =
            new VerificationServiceComponentHolder();

    // CopyOnWriteArrayList: safe for concurrent reads from request threads while OSGi
    // activation/deactivation writes on the framework thread; also safe to iterate without
    // external synchronization (stream(), addAll()), unlike Collections.synchronizedList.
    private final List<CredentialSignatureValidator> builtInValidators = new CopyOnWriteArrayList<>();
    private final List<CredentialSignatureValidator> externalValidators = new CopyOnWriteArrayList<>();

    private VerificationServiceComponentHolder() {

    }

    public static VerificationServiceComponentHolder getInstance() {

        return INSTANCE;
    }

    /** Called during bundle activation to register the built-in validators. */
    void addBuiltInValidator(CredentialSignatureValidator validator) {

        builtInValidators.add(validator);
    }

    /** Called during bundle deactivation to clear built-ins, preventing duplicates on reactivation. */
    void clearBuiltInValidators() {

        builtInValidators.clear();
    }

    /** Called by the OSGi @Reference binder when an external validator is registered. */
    public void addExternalValidator(CredentialSignatureValidator validator) {

        externalValidators.add(validator);
    }

    /** Called by the OSGi @Reference unbinder when an external validator is unregistered. */
    public void removeExternalValidator(CredentialSignatureValidator validator) {

        externalValidators.remove(validator);
    }

    /**
     * Look up a validator by its type key. External validators are checked first,
     * allowing them to override built-ins.
     *
     * @param type the validator type key (e.g. {@code "JWKS_URI"})
     * @return the matching validator, or {@link Optional#empty()} if none is registered
     */
    public Optional<CredentialSignatureValidator> getValidator(String type) {

        return Stream.concat(externalValidators.stream(), builtInValidators.stream())
                .filter(v -> v.getValidatorType().equals(type))
                .findFirst();
    }

    /** Returns all registered validators (external + built-in). */
    public List<CredentialSignatureValidator> getAllValidators() {

        List<CredentialSignatureValidator> all = new ArrayList<>();
        all.addAll(externalValidators);
        all.addAll(builtInValidators);
        return Collections.unmodifiableList(all);
    }
}
