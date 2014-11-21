package com.wwpass.springsecurity.web.authentication;

import com.wwpass.connection.WWPassConnection;
import com.wwpass.springsecurity.authentication.WwpassAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

/*
 *
 * @copyright (c) WWPass Corporation, 2013
 * @author Stanislav Panyushkin <s.panyushkin@wwpass.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
public final class WwpassAuthenticationFilter extends AbstractAuthenticationProcessingFilter{

	protected WwpassAuthenticationFilter() {
		super("/j_wwpass_security_check");
	}

	@Autowired
	private WWPassConnection conn;
	
	public Authentication attemptAuthentication(HttpServletRequest request,	
			HttpServletResponse response) throws AuthenticationException {
		
		if (!request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException("Authentication method not supported: " +
					request.getMethod());
		}
		
		String ticket = request.getParameter("ticket");
		
        String puid;
		try {
			ticket = conn.putTicket(ticket);
			puid = conn.getPUID(ticket); 
		} catch (UnsupportedEncodingException e) {
			throw new AuthenticationServiceException("Exception in WWPassConnection library: \n", e);
		} catch (IOException e) {
			throw new AuthenticationServiceException("Exception in WWPassConnection library: \n", e);
		} 
		
		if (puid == null) {
			throw new IllegalArgumentException("PUID cannot be null.");
		}
		
		request.getSession().setAttribute("puid", puid);
		
		
		WwpassAuthenticationToken authRequest = 
				new WwpassAuthenticationToken(null, puid, null);
		
		
		return this.getAuthenticationManager().authenticate(authRequest);
	}
	
	public void setWWPassConnection(WWPassConnection conn) {
		this.conn = conn;
	}

}
