/*
 *   DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *  
 *   Copyright (c) [2017] Payara Foundation and/or its affiliates. 
 *   All rights reserved.
 *  
 *   The contents of this file are subject to the terms of either the GNU
 *   General Public License Version 2 only ("GPL") or the Common Development
 *   and Distribution License("CDDL") (collectively, the "License").  You
 *   may not use this file except in compliance with the License.  You can
 *   obtain a copy of the License at
 *   https://github.com/payara/Payara/blob/master/LICENSE.txt
 *   See the License for the specific
 *   language governing permissions and limitations under the License.
 *  
 *   When distributing the software, include this License Header Notice in each
 *   file and include the License file at glassfish/legal/LICENSE.txt.
 *  
 *   GPL Classpath Exception:
 *   The Payara Foundation designates this particular file as subject to the 
 *   "Classpath" exception as provided by the Payara Foundation in the GPL 
 *   Version 2 section of the License file that accompanied this code.
 *  
 *   Modifications:
 *   If applicable, add the following below the License Header, with the fields
 *   enclosed by brackets [] replaced by your own identifying information:
 *   "Portions Copyright [year] [name of copyright owner]"
 *  
 *   Contributor(s):
 *   If you wish your version of this file to be governed by only the CDDL or
 *   only the GPL Version 2, indicate your decision by adding "[Contributor]
 *   elects to include this software in this distribution under the [CDDL or GPL
 *   Version 2] license."  If you don't indicate a single choice of license, a
 *   recipient has the option to distribute your version of this file under
 *   either the CDDL, the GPL Version 2 or to extend the choice of license to
 *   its licensees as provided above.  However, if you add GPL Version 2 code
 *   and therefore, elected the GPL Version 2 license, then the option applies
 *   only if the new code is made subject to such option by the copyright
 *   holder.
 */
package fish.payara.roles.api.auth;

import java.io.IOException;
import java.security.Principal;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import static javax.security.auth.message.AuthStatus.SEND_FAILURE;
import static javax.security.auth.message.AuthStatus.SEND_SUCCESS;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.PasswordValidationCallback;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.glassfish.hk2.api.ServiceLocator;
import javax.servlet.http.HttpSession;

/**
 *
 * @author Michael Ranaldo <michael@ranaldo.co.uk>
 */
public class RolesCDIAuthModule implements ServerAuthModule {

    private CallbackHandler handler = null;

    private String loginPage = null;
    private String loginErrorPage = null;
    private String ORIGINAL_REQUEST_PATH = "origRequestPath";
    private static final Class[] SUPPORTED_MESSAGE_TYPES
            = new Class[]{HttpServletRequest.class, HttpServletResponse.class};

    /**
     * Initialize the AuthModule.
     *
     * @param requestPolicy
     * @param responsePolicy
     * @param handler
     * @param options Options set within the domain.xml; can also be configued via Admin Console ->
     * @throws AuthException
     */
    @Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler,
            Map options) throws AuthException {
        this.handler = handler;

        // Need to provide a way to login and somewhere to go when you fail
        if (options != null) {
            this.loginPage = (String) options.get("loginPage");
            if (loginPage == null) {
                throw new AuthException("'loginPage' "
                        + "must be supplied as a property in the provider-config "
                        + "in the domain.xml file!");
            }
            this.loginErrorPage = (String) options.get("loginErrorPage");
            if (loginErrorPage == null) {
                throw new AuthException("'loginErrorPage' "
                        + "must be supplied as a property in the provider-config "
                        + "in the domain.xml file!");
            }
            
        }
    }

    /**
     * Get supported message types.
     *
     * @return
     */
    @Override
    public Class[] getSupportedMessageTypes() {
        return SUPPORTED_MESSAGE_TYPES;
    }

    /**
     * Validate a given request, comparing the submitted principals to the allowed roles.
     *
     * @param messageInfo
     * @param clientSubject
     * @param serviceSubject
     * @return
     * @throws AuthException
     */
    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject)
            throws AuthException {
        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();

        // Check if our session has already been authenticated
        Principal userPrincipal = request.getUserPrincipal();
        if (userPrincipal != null) {
            try {
                handler.handle(new Callback[]{new CallerPrincipalCallback(clientSubject, userPrincipal)});
                return AuthStatus.SUCCESS;
            } catch (IOException | UnsupportedCallbackException ex) {
                AuthException ae = new AuthException();
                ae.initCause(ex);
                throw ae;
            }
        }

        // See if the username / password has been passed in...
        String username = request.getParameter("j_username");
        String password = request.getParameter("j_password");
        if ((username == null) || (password == null) || !request.getMethod().equalsIgnoreCase("post")) {
            // Not passed in, show the login page...
            String origPath = request.getRequestURI();
            String queryString = request.getQueryString();

            if ((queryString != null) && (!queryString.isEmpty())) {
                origPath += "?" + queryString;
            }

            request.getSession().setAttribute(ORIGINAL_REQUEST_PATH, origPath);
            RequestDispatcher rd = request.getRequestDispatcher(loginPage);

            try {
                rd.forward(request, response);
            } catch (IOException | ServletException ex) {
                AuthException authException = new AuthException();
                authException.initCause(ex);
                throw authException;
            }

            return AuthStatus.SEND_CONTINUE;
        }

        PasswordValidationCallback pvCallback = new PasswordValidationCallback(clientSubject, username,
                password.toCharArray());
        try {
            handler.handle(new Callback[]{pvCallback});
        } catch (IOException | UnsupportedCallbackException ex) {
            AuthException ae = new AuthException();
            ae.initCause(ex);
            throw ae;
        }
        // Register the session as authenticated
        messageInfo.getMap().put("javax.servlet.http.registerSession", Boolean.TRUE.toString());

        // Redirect to original path
        try {
            String origRequest = (String) request.getSession().getAttribute(ORIGINAL_REQUEST_PATH);

            if (origRequest == null) {
                origRequest = ;
            }

            response.sendRedirect(response.encodeRedirectURL(origRequest));
        } catch (IOException ex) {
            AuthException ae = new AuthException();
            ae.initCause(ex);
            throw ae;
        }

        // Continue...
        return AuthStatus.SUCCESS;
    }

    /**
     * Return a success.
     *
     * @param messageInfo
     * @param serviceSubject
     * @return
     * @throws AuthException
     */
    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        return SEND_SUCCESS;
    }

    /**
     * Wipes out the principals.
     *
     * @param messageInfo
     * @param subject
     * @throws AuthException
     */
    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        if (subject != null) {
            subject.getPrincipals().clear();
        }
    }

}
