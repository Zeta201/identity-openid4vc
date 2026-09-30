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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal;

import org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationConfigMgtService;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationCoreService;

/**
 * Data holder for the VP authenticator bundle.
 */
public class PresentationAuthenticatorDataHolder {

    private static final PresentationAuthenticatorDataHolder instance = new PresentationAuthenticatorDataHolder();

    private PresentationCoreService vpSessionService;
    private PresentationConfigMgtService vpConfigMgtService;

    private PresentationAuthenticatorDataHolder() {

    }

    public static PresentationAuthenticatorDataHolder getInstance() {

        return instance;
    }

    public PresentationCoreService getPresentationSessionService() {

        return vpSessionService;
    }

    public void setPresentationSessionService(PresentationCoreService vpSessionService) {

        this.vpSessionService = vpSessionService;
    }

    public PresentationConfigMgtService getPresentationConfigMgtService() {

        return vpConfigMgtService;
    }

    public void setPresentationConfigMgtService(PresentationConfigMgtService vpConfigMgtService) {

        this.vpConfigMgtService = vpConfigMgtService;
    }
}
