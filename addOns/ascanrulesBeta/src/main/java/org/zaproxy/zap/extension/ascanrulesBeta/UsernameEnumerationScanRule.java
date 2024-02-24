/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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

import difflib.Delta;
import difflib.DiffUtils;
import difflib.Patch;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.http.ComparableResponse;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.zap.authentication.FormBasedAuthenticationMethodType.FormBasedAuthenticationMethod;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.model.Context;

/**
 * The UsernameEnumerationScanRule identifies vulnerabilities with the login page or "forgot
 * password" page. It identifies urls where the page results depend on whether the username supplied
 * is valid or invalid using a differentiation based approach
 *
 * <p>TODO: how to avoid false positives on the password field?
 *
 * @author 70pointer
 */
public class UsernameEnumerationScanRule extends AbstractAppPlugin
        implements CommonActiveScanRuleInfo {

    private static final Logger LOGGER = LogManager.getLogger(UsernameEnumerationScanRule.class);

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                    CommonAlertTag.WSTG_V42_IDNT_04_ACCOUNT_ENUMERATION);

    private static ExtensionAuthentication extAuth =
            (ExtensionAuthentication)
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionAuthentication.NAME);

    private static final float SIMILARITY_THRESHOLD = 0.80f;

    @Override
    public int getId() {
        return 40023;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.usernameenumeration.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.usernameenumeration.desc");
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanbeta.usernameenumeration.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanbeta.usernameenumeration.refs");
    }

    @Override
    public void init() {
        LOGGER.debug("Initialising");

        if (!shouldContinue(extAuth.getModel().getSession().getContexts())) {
            LOGGER.info(
                    "There does not appear to be any configured contexts using Form-based Authentication. Further attempts during the current scan will be skipped.");
            this.getParent().pluginSkipped(this);
        }
    }

    /**
     * looks for username enumeration in the login page, by changing the username field to be a
     * valid / invalid user, and looking for differences in the response
     */
    @Override
    public void scan() {

        // the technique to determine if usernames can be enumerated is as follows:
        //
        // 1) Request the original URL n times. (The original URL is assumed to have a valid
        // username, if not a valid password).
        // 2) Compare all the n valid username responses.
        // 3) for each parameter in the original URL (ie, for URL params, form params, and cookie
        // params)
        // 4) Change the current parameter (which we assume is the username parameter) to an invalid
        // username (randomly), and request the URL n times.
        // 5) Compare all the n invalid username responses.
        // 6) If valid username response <> invalid username response, then there is a Username
        // Enumeration issue on the current parameter

        try {
            boolean loginUrl = false;

            // Are we dealing with a login url in any of the contexts of which this uri is part
            URI requestUri = getBaseMsg().getRequestHeader().getURI();

            List<Context> contextList =
                    extAuth.getModel().getSession().getContextsForUrl(requestUri.toString());

            // now loop, and see if the url is a login url in each of the contexts in turn...
            for (Context context : contextList) {
                URI loginUri = extAuth.getLoginRequestURIForContext(context);
                if (loginUri != null
                        && requestUri.getScheme().equals(loginUri.getScheme())
                        && requestUri.getHost().equals(loginUri.getHost())
                        && requestUri.getPort() == loginUri.getPort()
                        && requestUri.getPath().equals(loginUri.getPath())) {
                    // we got this far.. only the method (GET/POST), user details, query params,
                    // fragment, and POST params are possibly different from the login page.
                    loginUrl = true;
                    LOGGER.info(
                            "{} falls within a context, and is the defined Login URL. Scanning for possible Username Enumeration vulnerability.",
                            requestUri);
                    break;
                }
            }

            if (!loginUrl) {
                LOGGER.debug("{} is not a defined Login URL.", requestUri);
                return; // No need to continue for this URL
            }

            // find all params set in the request (GET/POST/Cookie)
            TreeSet<HtmlParameter> htmlParams = new TreeSet<>();
            htmlParams.addAll(getBaseMsg().getRequestHeader().getCookieParams());
            htmlParams.addAll(getBaseMsg().getFormParams());
            htmlParams.addAll(getBaseMsg().getUrlParams());

            int numberOfRequests = 0;
            if (this.getAttackStrength() == AttackStrength.INSANE) {
                numberOfRequests = 50;
            } else if (this.getAttackStrength() == AttackStrength.HIGH) {
                numberOfRequests = 15;
            } else if (this.getAttackStrength() == AttackStrength.MEDIUM) {
                numberOfRequests = 5;
            } else if (this.getAttackStrength() == AttackStrength.LOW) {
                numberOfRequests = 3;
            }

            // 1) Request the original URL n times. (The original URL is assumed to have a valid
            // username, if not a valid password).
            // make sure to manually handle all redirects, and cookies that may be set in response.

            HttpMessage prevMsgA = null; // previous valid username response

            for (int i = 0; i < numberOfRequests; i++) {

                HttpMessage msgCpy = getNewMsg(); // clone the request, but not the response

                sendAndReceive(
                        msgCpy, false,
                        false); // request the URL, but do not automatically follow redirects.

                // get all cookies set in the response
                TreeSet<HtmlParameter> cookies = msgCpy.getResponseHeader().getCookieParams();

                int redirectCount = 0;
                while (HttpStatusCode.isRedirection(msgCpy.getResponseHeader().getStatusCode())) {
                    redirectCount++;

                    LOGGER.debug(
                            "Following redirect {} for message {} of {} iterations of the original query",
                            redirectCount,
                            i,
                            numberOfRequests);

                    // and manually follow the redirect
                    // create a new message from scratch
                    HttpMessage msgRedirect = new HttpMessage();

                    // create a new URI from the absolute location returned, and interpret it as
                    // escaped
                    // note that the standard says that the Location returned should be absolute,
                    // but it ain't always so...
                    URI newLocation =
                            new URI(
                                    msgCpy.getResponseHeader().getHeader(HttpFieldsNames.LOCATION),
                                    true);
                    try {
                        msgRedirect.getRequestHeader().setURI(newLocation);
                    } catch (Exception e) {
                        // the Location field contents may not be standards compliant. Lets generate
                        // a uri to use as a workaround where a relative path was
                        // given instead of an absolute one
                        URI newLocationWorkaround =
                                new URI(
                                        msgCpy.getRequestHeader().getURI(),
                                        msgCpy.getResponseHeader()
                                                .getHeader(HttpFieldsNames.LOCATION),
                                        true);
                        // try again, except this time, if it fails, don't try to handle it
                        LOGGER.debug(
                                "The Location [{}] specified in a redirect was not valid (not absolute?). Trying absolute workaround url [{}]",
                                newLocation,
                                newLocationWorkaround);
                        msgRedirect.getRequestHeader().setURI(newLocationWorkaround);
                    }
                    msgRedirect
                            .getRequestHeader()
                            .setMethod(HttpRequestHeader.GET); // it's always a GET for a redirect
                    msgRedirect
                            .getRequestHeader()
                            .setVersion(getBaseMsg().getRequestHeader().getVersion());
                    msgRedirect
                            .getRequestHeader()
                            .setContentLength(0); // since we send a GET, the body will be 0 long
                    if (!cookies.isEmpty()) {
                        // if a previous request sent back a cookie that has not since been
                        // invalidated, we need to set that cookie when following redirects, as a
                        // browser would
                        msgRedirect.getRequestHeader().setCookieParams(cookies);
                    }

                    LOGGER.debug("DEBUG: Following redirect to [{}]", newLocation);
                    sendAndReceive(msgRedirect, false, false); // do NOT redirect.. handle it here

                    // handle scenario where a cookie is unset in a subsequent iteration, or where
                    // the same cookie name is later re-assigned a different value
                    // ie, in these cases, do not simply (and dumbly) accumulate cookie detritus.
                    // first get all cookies set in the response
                    TreeSet<HtmlParameter> cookiesTemp =
                            msgRedirect.getResponseHeader().getCookieParams();
                    for (Iterator<HtmlParameter> redirectSetsCookieIterator =
                                    cookiesTemp.iterator();
                            redirectSetsCookieIterator.hasNext(); ) {
                        HtmlParameter cookieJustSet = redirectSetsCookieIterator.next();
                        // loop through each of the cookies we know about in cookies, to see if it
                        // matches by name.
                        // if so, delete that cookie, and add the one that was just set to cookies.
                        // if not, add the one that was just set to cookies.
                        for (Iterator<HtmlParameter> knownCookiesIterator = cookies.iterator();
                                knownCookiesIterator.hasNext(); ) {
                            HtmlParameter knownCookie = knownCookiesIterator.next();
                            if (cookieJustSet.getName().equals(knownCookie.getName())) {
                                knownCookiesIterator.remove();
                                break; // out of the loop for known cookies, back to the next cookie
                                // set in the response
                            }
                        } // end of loop for cookies we already know about
                        // we can now safely add the cookie that was just set into cookies, knowing
                        // it does not clash with anything else in there.
                        cookies.add(cookieJustSet);
                    } // end of for loop for cookies just set in the redirect

                    msgCpy = msgRedirect; // store the last redirect message into the MsgCpy, as we
                    // will be using it's output in a moment..
                } // end of loop to follow redirects

                // now that the redirections have all been handled.. was the request finally a
                // success or not?  Successful or Failed Logins would normally both return an OK
                // HTTP status
                if (!HttpStatusCode.isSuccess(msgCpy.getResponseHeader().getStatusCode())) {
                    LOGGER.debug(
                            "The original URL [{}] returned a non-OK HTTP status {} (after {} of {} steps). Could be indicative of SQL Injection, or some other error. The URL is not stable enough to look at Username Enumeration",
                            getBaseMsg().getRequestHeader().getURI(),
                            msgCpy.getResponseHeader().getStatusCode(),
                            i,
                            numberOfRequests);
                    return; // we have not even got as far as looking at the parameters, so just
                    // abort straight out of the method
                }

                LOGGER.debug("Done following redirects!");

                // 2) Compare all the n valid username responses.

                if (i > 0) {
                    ComparableResponse prevResponse = new ComparableResponse(prevMsgA, null);
                    ComparableResponse currResponse = new ComparableResponse(msgCpy, null);

                    // optimisation step: if the response is different already, then the URL
                    // output is not stable, and we can abort now, and save some time
                    if (currResponse.compareWith(prevResponse) < SIMILARITY_THRESHOLD) {
                        // this might occur if the output returned for the URL changed mid-way.
                        // Perhaps
                        // a CAPTCHA has fired, or a WAF has kicked in.  Let's abort now so.
                        LOGGER.debug(
                                "The original URL [{}] does not produce stable output (at {} of {} steps).  There is no static element in the output that can be used as a basis of comparison for the result of requesting URLs with the parameter values modified. Perhaps a CAPTCHA or WAF has kicked in!!",
                                getBaseMsg().getRequestHeader().getURI(),
                                i + 1,
                                numberOfRequests);
                        return; // we have not even got as far as looking at the parameters, so just
                        // abort straight out of the method
                    }
                }

                prevMsgA = msgCpy;
            }

            // 3) for each parameter in the original URL (ie, for URL params, form params, and
            // cookie params)

            HttpMessage prevMsgB = null; // previous invalid username response

            for (Iterator<HtmlParameter> iter = htmlParams.iterator(); iter.hasNext(); ) {

                HttpMessage msgModifiedParam = getNewMsg();
                HtmlParameter currentHtmlParameter = iter.next();

                LOGGER.debug(
                        "Handling [{}] parameter [{}], with value [{}]",
                        currentHtmlParameter.getType(),
                        currentHtmlParameter.getName(),
                        currentHtmlParameter.getValue());

                // 4) Change the current parameter value (which we assume is the username parameter)
                // to an invalid username (randomly), and request the URL n times.

                // get a random user name the same length as the original!
                String invalidUsername =
                        RandomStringUtils.randomAlphabetic(currentHtmlParameter.getValue().length())
                                .toLowerCase(Locale.ROOT);

                LOGGER.debug("The invalid username chosen was [{}]", invalidUsername);

                TreeSet<HtmlParameter> requestParams = null;
                if (currentHtmlParameter.getType().equals(HtmlParameter.Type.cookie)) {
                    requestParams = msgModifiedParam.getRequestHeader().getCookieParams();
                    requestParams.remove(currentHtmlParameter);
                    requestParams.add(
                            new HtmlParameter(
                                    currentHtmlParameter.getType(),
                                    currentHtmlParameter.getName(),
                                    invalidUsername));
                    msgModifiedParam.setCookieParams(requestParams);
                } else if (currentHtmlParameter.getType().equals(HtmlParameter.Type.url)) {
                    requestParams = msgModifiedParam.getUrlParams();
                    requestParams.remove(currentHtmlParameter);
                    requestParams.add(
                            new HtmlParameter(
                                    currentHtmlParameter.getType(),
                                    currentHtmlParameter.getName(),
                                    invalidUsername));
                    msgModifiedParam.setGetParams(requestParams);
                } else if (currentHtmlParameter.getType().equals(HtmlParameter.Type.form)) {
                    requestParams = msgModifiedParam.getFormParams();
                    requestParams.remove(currentHtmlParameter);
                    requestParams.add(
                            new HtmlParameter(
                                    currentHtmlParameter.getType(),
                                    currentHtmlParameter.getName(),
                                    invalidUsername));
                    msgModifiedParam.setFormParams(requestParams);
                }

                LOGGER.debug(
                        "About to loop for {} iterations with an incorrect user of the same length",
                        numberOfRequests);

                boolean continueForParameter = true;

                for (int i = 0; i < numberOfRequests && continueForParameter; i++) {

                    HttpMessage msgCpy = msgModifiedParam;

                    sendAndReceive(msgCpy, false, false);

                    TreeSet<HtmlParameter> cookies = msgCpy.getResponseHeader().getCookieParams();

                    int redirectCount = 0;
                    while (HttpStatusCode.isRedirection(
                            msgCpy.getResponseHeader().getStatusCode())) {
                        redirectCount++;

                        LOGGER.debug(
                                "Following redirect {} for message {} of {} iterations of the modified query.",
                                redirectCount,
                                i,
                                numberOfRequests);

                        // manually follow the redirect
                        // create a new message from scratch
                        HttpMessage msgRedirect = new HttpMessage();

                        // create a new URI from the absolute location returned, and interpret it as
                        // escaped
                        // note that the standard says that the Location returned should be
                        // absolute, but it ain't always so...
                        URI newLocation =
                                new URI(
                                        msgCpy.getResponseHeader()
                                                .getHeader(HttpFieldsNames.LOCATION),
                                        true);
                        try {
                            msgRedirect.getRequestHeader().setURI(newLocation);
                        } catch (Exception e) {
                            // the Location field contents may not be standards compliant. Lets
                            // generate a uri to use as a workaround where a relative path was
                            // given instead of an absolute one
                            URI newLocationWorkaround =
                                    new URI(
                                            msgCpy.getRequestHeader().getURI(),
                                            msgCpy.getResponseHeader()
                                                    .getHeader(HttpFieldsNames.LOCATION),
                                            true);
                            // try again, except this time, if it fails, don't try to handle it
                            LOGGER.debug(
                                    "The Location [{}] specified in a redirect was not valid (not absolute?). Trying absolute workaround url [{}]",
                                    newLocation,
                                    newLocationWorkaround);
                            msgRedirect.getRequestHeader().setURI(newLocationWorkaround);
                        }
                        msgRedirect.getRequestHeader().setMethod(HttpRequestHeader.GET);
                        msgRedirect
                                .getRequestHeader()
                                .setVersion(getBaseMsg().getRequestHeader().getVersion());
                        msgRedirect
                                .getRequestHeader()
                                .setContentLength(
                                        0); // since we send a GET, the body will be 0 long
                        if (!cookies.isEmpty()) {
                            // if a previous request sent back a cookie that has not since been
                            // invalidated, we need to set that cookie when following redirects, as
                            // a browser would
                            msgRedirect.getRequestHeader().setCookieParams(cookies);
                        }

                        sendAndReceive(
                                msgRedirect, false, false); // do NOT redirect.. handle it here

                        // handle scenario where a cookie is unset in a subsequent iteration, or
                        // where the same cookie name is later re-assigned a different value
                        // ie, in these cases, do not simply (and dumbly) accumulate cookie
                        // detritus.
                        // first get all cookies set in the response
                        TreeSet<HtmlParameter> cookiesTemp =
                                msgRedirect.getResponseHeader().getCookieParams();
                        for (Iterator<HtmlParameter> redirectSetsCookieIterator =
                                        cookiesTemp.iterator();
                                redirectSetsCookieIterator.hasNext(); ) {
                            HtmlParameter cookieJustSet = redirectSetsCookieIterator.next();
                            // loop through each of the cookies we know about in cookies, to see if
                            // it matches by name.
                            // if so, delete that cookie, and add the one that was just set to
                            // cookies.
                            // if not, add the one that was just set to cookies.
                            for (Iterator<HtmlParameter> knownCookiesIterator = cookies.iterator();
                                    knownCookiesIterator.hasNext(); ) {
                                HtmlParameter knownCookie = knownCookiesIterator.next();
                                if (cookieJustSet.getName().equals(knownCookie.getName())) {
                                    knownCookiesIterator.remove();
                                    break; // out of the loop for known cookies, back to the next
                                    // cookie set in the response
                                }
                            } // end of loop for cookies we already know about
                            // we can now safely add the cookie that was just set into cookies,
                            // knowing it does not clash with anything else in there.
                            cookies.add(cookieJustSet);
                        } // end of for loop for cookies just set in the redirect

                        msgCpy = msgRedirect; // store the last redirect message into the MsgCpy, as
                        // we will be using it's output in a moment..
                    } // end of loop to follow redirects

                    // now that the redirections have all been handled.. was the request finally a
                    // success or not?  Successful or Failed Logins would normally both return an OK
                    // HTTP status
                    if (!HttpStatusCode.isSuccess(msgCpy.getResponseHeader().getStatusCode())) {
                        LOGGER.debug(
                                "The modified URL [{}] returned a non-OK HTTP status {} (after {} of {} steps for [{}] parameter {}). Could be indicative of SQL Injection, or some other error. The URL is not stable enough to look at Username Enumeration",
                                msgModifiedParam.getRequestHeader().getURI(),
                                msgCpy.getResponseHeader().getStatusCode(),
                                i + 1,
                                numberOfRequests,
                                currentHtmlParameter.getType(),
                                currentHtmlParameter.getName());
                        continueForParameter = false;
                        continue; // skip directly to the next parameter
                    }

                    LOGGER.debug("Done following redirects!");

                    //	5) Compare all the n invalid username responses.

                    // optimisation step: if the response is different already, then the URL
                    // output is not stable, and we can abort now, and save some time
                    if (i > 0) {
                        ComparableResponse prevResponse = new ComparableResponse(prevMsgB, null);
                        ComparableResponse currResponse = new ComparableResponse(msgCpy, null);

                        if (currResponse.compareWith(prevResponse) < SIMILARITY_THRESHOLD) {
                            // this might occur if the output returned for the URL changed mid-way.
                            // Perhaps a CAPTCHA has fired, or a WAF has kicked in.  Let's abort now
                            // so.
                            LOGGER.debug(
                                    "The modified URL [{}] (for [{}] parameter {}) does not produce stable output (after {} of {} steps). There is no static element in the output that can be used as a basis of comparison with the static output of the original query. Perhaps a CAPTCHA or WAF has kicked in!!",
                                    msgModifiedParam.getRequestHeader().getURI(),
                                    currentHtmlParameter.getType(),
                                    currentHtmlParameter.getName(),
                                    i + 1,
                                    numberOfRequests);
                            continueForParameter = false;
                            continue; // skip directly to the next parameter.
                            // Note: if a CAPTCHA or WAF really has fired, the results of subsequent
                            // iterations will likely not be accurate..
                        }
                    }

                    prevMsgB = msgCpy;
                }

                // if we didn't hit something with one of the iterations for the parameter (ie, if
                // the output when changing the param is stable),
                // check if the parameter might be vulnerable by comparing its response with the
                // original response for a valid login
                if (prevMsgB != null && continueForParameter) {

                    //	6) If valid username response <> invalid username response, then there is a
                    // Username Enumeration issue on the current parameter
                    ComparableResponse validUsernameResponse =
                            new ComparableResponse(prevMsgA, null);
                    ComparableResponse invalidUsernameResponse =
                            new ComparableResponse(prevMsgB, null);

                    StringBuilder validUsernameRes = new StringBuilder(250);
                    validUsernameRes
                            .append(prevMsgA.getResponseHeader().getHeadersAsString())
                            .append(prevMsgA.getResponseBody());
                    StringBuilder invalidUsernameRes = new StringBuilder(250);
                    invalidUsernameRes
                            .append(prevMsgB.getResponseHeader().getHeadersAsString())
                            .append(prevMsgB.getResponseBody());

                    if (validUsernameResponse.compareWith(invalidUsernameResponse)
                            < SIMILARITY_THRESHOLD) {
                        // calculate line level diffs of the 2 responses to aid the
                        // user in deciding if the match is a false positive
                        // get the diff as a series of patches
                        Patch<String> diffpatch =
                                DiffUtils.diff(
                                        new LinkedList<>(
                                                Arrays.asList(
                                                        String.valueOf(validUsernameRes)
                                                                .split("\\n"))),
                                        new LinkedList<>(
                                                Arrays.asList(
                                                        String.valueOf(invalidUsernameRes)
                                                                .split("\\n"))));

                        int numberofDifferences = diffpatch.getDeltas().size();

                        StringBuilder tempDiff = new StringBuilder(250);
                        for (Delta<String> delta : diffpatch.getDeltas()) {
                            String changeType = null;
                            if (delta.getType() == Delta.TYPE.CHANGE) changeType = "Changed Text";
                            else if (delta.getType() == Delta.TYPE.DELETE)
                                changeType = "Deleted Text";
                            else if (delta.getType() == Delta.TYPE.INSERT)
                                changeType = "Inserted text";
                            else changeType = "Unknown change type [" + delta.getType() + "]";

                            tempDiff.append("\n(" + changeType + ")\n"); // blank line before
                            tempDiff.append(
                                    "Output for Valid Username  : "
                                            + delta.getOriginal()
                                            + "\n"); // no blank lines
                            tempDiff.append(
                                    "\nOutput for Invalid Username: "
                                            + delta.getRevised()
                                            + "\n"); // blank line before
                        }
                        String diffAB = tempDiff.toString();
                        String extraInfo =
                                Constant.messages.getString(
                                        "ascanbeta.usernameenumeration.alert.extrainfo",
                                        currentHtmlParameter.getType(),
                                        currentHtmlParameter.getName(),
                                        currentHtmlParameter.getValue(), // original value
                                        invalidUsername, // new value
                                        diffAB, // the differences between the two sets of output
                                        numberofDifferences);
                        String attack =
                                Constant.messages.getString(
                                        "ascanbeta.usernameenumeration.alert.attack",
                                        currentHtmlParameter.getType(),
                                        currentHtmlParameter.getName());
                        String vulnname =
                                Constant.messages.getString("ascanbeta.usernameenumeration.name");
                        String vulndesc =
                                Constant.messages.getString("ascanbeta.usernameenumeration.desc");
                        String vulnsoln =
                                Constant.messages.getString("ascanbeta.usernameenumeration.soln");

                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_LOW)
                                .setName(vulnname)
                                .setDescription(vulndesc)
                                .setParam(currentHtmlParameter.getName())
                                .setAttack(attack)
                                .setOtherInfo(extraInfo)
                                .setSolution(vulnsoln)
                                .setMessage(getBaseMsg())
                                .raise();

                    } else {
                        LOGGER.debug(
                                "[{}] parameter [{}] looks ok (Invalid Usernames cannot be distinguished from Valid usernames)",
                                currentHtmlParameter.getType(),
                                currentHtmlParameter.getName());
                    }
                }
            } // end of the for loop around the parameter list

        } catch (Exception e) {
            // Do not try to internationalise this.. we need an error message in any event..
            // if it's in English, it's still better than not having it at all.
            LOGGER.error("An error occurred checking a url for Username Enumeration issues", e);
        }
    }

    @Override
    public int getRisk() {
        return Alert.RISK_INFO;
    }

    private boolean shouldContinue(List<Context> contextList) {
        boolean hasAuth = false;
        for (Context context : contextList) {
            if (context.getAuthenticationMethod() instanceof FormBasedAuthenticationMethod) {
                hasAuth = true;
                break;
            }
        }
        return hasAuth;
    }

    @Override
    public int getCweId() {
        return 200; // CWE-200: Information Exposure
    }

    @Override
    public int getWascId() {
        return 13; // Info leakage
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
