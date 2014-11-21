package com.wwpass.springsecurity.authentication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Collection;


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
@Component
public class WwpassAuthenticationProvider implements AuthenticationProvider {

	private final AuthenticationUserDetailsService<WwpassAuthenticationToken> userDetailsService;

	private final static String DEFAULT_WWPASS_ROLE = "ROLE_USER";
	
	private String wwpassUserRole;
	
	@Autowired
	public WwpassAuthenticationProvider(AuthenticationUserDetailsService<WwpassAuthenticationToken> userDetailsService) {
		this.userDetailsService = userDetailsService;
	}
	
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		
		if (!supports(authentication.getClass())) {
            return null;
        }
		
		if (authentication instanceof WwpassAuthenticationToken) {
			WwpassAuthenticationToken token =	(WwpassAuthenticationToken) authentication;
			
			String puid = token.getPuid();
			
			UserDetails user = null;
			if (puid != null) {
				user = userDetailsService.loadUserDetails(token);
			}
			if (user == null) {
				throw new UsernameNotFoundException("PUID not found.");
			}
			Collection<? extends GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(getWwpassUserRole());
				
			return new WwpassAuthenticationToken(user, puid, authorities);
		}
		
		return null;
	}

	public boolean supports(Class<?> authentication) {
		return WwpassAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public String getWwpassUserRole() {
		if (wwpassUserRole == null) {
			this.wwpassUserRole = DEFAULT_WWPASS_ROLE;
		}
		return wwpassUserRole;
	}

	public void setWwpassUserRole(String wwpassUserRole) {
		this.wwpassUserRole = wwpassUserRole;
	}

	
}
