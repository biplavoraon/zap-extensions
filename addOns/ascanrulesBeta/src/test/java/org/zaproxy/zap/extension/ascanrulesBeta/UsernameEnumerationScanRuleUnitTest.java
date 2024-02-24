/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrulesBeta;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.Map;
import java.util.TreeSet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.NanoServerHandler;

import fi.iki.elonen.NanoHTTPD;

class UsernameEnumerationScanRuleUnitTest extends ActiveScannerTest<UsernameEnumerationScanRule> {
    private static final String RESPONSE_BODY =
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec mattis ex ac orci consectetur viverra. Aenean porttitor tincidunt ligula. Suspendisse et ornare justo. Fusce vel maximus est. Donec id arcu nec justo egestas hendrerit. Sed pulvinar ultrices ultricies. Mauris ultrices odio non tellus mattis, id pharetra justo porta. Donec venenatis ante ac nisi blandit gravida. Nunc tellus dolor, finibus nec placerat ac, ullamcorper sit amet tellus.";

    private static final String VALID_RESPONSE =
            String.format(
                    "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                            + "<html><head></head><body>%s</body></html>",
                    RESPONSE_BODY);

    private static final String INVALID_RESPONSE =
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                    + "<html><head></head><body>Lorem ipsum</body></html>";

    private ExtensionAuthentication extensionAuthentication;
    private Context context;

    @BeforeEach
    void setup() throws Exception {
        extensionAuthentication = mock(ExtensionAuthentication.class, RETURNS_DEEP_STUBS);
        context = mock(Context.class);
        Field field = UsernameEnumerationScanRule.class.getDeclaredField("extAuth");
        field.setAccessible(true);
        field.set(null, extensionAuthentication);
    }

    @Override
    protected UsernameEnumerationScanRule createScanner() {
        return new UsernameEnumerationScanRule();
    }

    @Disabled("Fails due to session/context involvement")
    @Override
    protected void shouldSendReasonableNumberOfMessages(
            AttackStrength strength, int maxNumberMessages, String defaultPath)
            throws HttpMalformedHeaderException {
        // Disabled - Fails due to session/context involvement
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(200)));
        assertThat(wasc, is(equalTo(13)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_IDNT_04_ACCOUNT_ENUMERATION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_IDNT_04_ACCOUNT_ENUMERATION.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_IDNT_04_ACCOUNT_ENUMERATION.getValue())));
    }

    @Test
    void shouldRaiseAlertIfNotMatch() throws Exception {
        // Given
        String path = "/test";
        HttpMessage msg = getHttpMessage(path);
        String username = "user1";
        TreeSet<HtmlParameter> cookies = parameters(cookieParam("username", username));
        msg.getRequestHeader().setCookieParams(cookies);

        nano.addHandler(new UsernameDiffResponseHandler(path, username));

        when(extensionAuthentication.getModel().getSession().getContexts())
                .thenReturn(Collections.singletonList(context));
        when(extensionAuthentication.getModel().getSession().getContextsForUrl(anyString()))
                .thenReturn(Collections.singletonList(context));
        when(extensionAuthentication.getLoginRequestURIForContext(context))
                .thenReturn(msg.getRequestHeader().getURI());

        // When
        rule.init(msg, parent);
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldNotRaiseAlertIfMatch() throws Exception {
        // Given
        String path = "/test";
        HttpMessage msg = getHttpMessage(path);
        String username = "user1";
        TreeSet<HtmlParameter> cookies = parameters(cookieParam("username", username));
        msg.getRequestHeader().setCookieParams(cookies);

        nano.addHandler(new UsernameSameResponseHandler(path));

        when(extensionAuthentication.getModel().getSession().getContexts())
                .thenReturn(Collections.singletonList(context));
        when(extensionAuthentication.getModel().getSession().getContextsForUrl(anyString()))
                .thenReturn(Collections.singletonList(context));
        when(extensionAuthentication.getLoginRequestURIForContext(context))
                .thenReturn(msg.getRequestHeader().getURI());

        // When
        rule.init(msg, parent);
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    private static HtmlParameter cookieParam(String name, String value) {
        return param(HtmlParameter.Type.cookie, name, value);
    }

    private static HtmlParameter param(HtmlParameter.Type type, String name, String value) {
        return new HtmlParameter(type, name, value);
    }

    private static TreeSet<HtmlParameter> parameters(HtmlParameter... params) {
        TreeSet<HtmlParameter> parameters = new TreeSet<>();
        if (params == null || params.length == 0) {
            return parameters;
        }
        Collections.addAll(parameters, params);
        return parameters;
    }

    // Returns different response for invalid usernames
    private static class UsernameDiffResponseHandler extends NanoServerHandler {
        private final String username;

        public UsernameDiffResponseHandler(String name, String username) {
            super(name);
            this.username = username;
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            if (session.getCookies().read("username").equals(username)) {
                return newFixedLengthResponse(
                        NanoHTTPD.Response.Status.OK, "text/html", VALID_RESPONSE);
            }
            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.OK, "text/html", INVALID_RESPONSE);
        }
    }

    // Returns same response for both valid and invalid usernames
    private static class UsernameSameResponseHandler extends NanoServerHandler {

        public UsernameSameResponseHandler(String name) {
            super(name);
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.OK, "text/html", VALID_RESPONSE);
        }
    }
}
