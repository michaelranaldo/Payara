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

import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import static javax.security.auth.message.AuthStatus.SEND_FAILURE;
import static javax.security.auth.message.AuthStatus.SEND_SUCCESS;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 *
 * @author Michael Ranaldo <michael@ranaldo.co.uk>
 */
public class RolesCDIAuthModule implements ServerAuthModule {
    
    private CallbackHandler handler = null;
    
    private static final Class[] SUPPORTED_MESSAGE_TYPES 
            = new Class[] { HttpServletRequest.class, HttpServletResponse.class };
    
    @Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, 
            Map options) throws AuthException {
        this.handler = handler;
        
    }

    @Override
    public Class[] getSupportedMessageTypes() {
        return SUPPORTED_MESSAGE_TYPES;
    }

    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) 
            throws AuthException {
        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();
        String authHeader = request.getHeader("Authorization");
        
        // check if this returns the proper user
        clientSubject.getPrincipals();
        // otherwise try this
        serviceSubject.getPrincipals();
        
        boolean isMandatoryMessagePolicy = Boolean.valueOf(
                (String) messageInfo.getMap().get("javax.security.auth.message.MessagePolicy.isMandatory"));
        
        if(!isMandatoryMessagePolicy) {
            return SEND_SUCCESS;
        } else {
            return SEND_FAILURE;
        }
    }

    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
