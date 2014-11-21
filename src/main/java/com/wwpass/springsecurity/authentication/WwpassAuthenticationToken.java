package com.wwpass.springsecurity.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

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
public class WwpassAuthenticationToken extends AbstractAuthenticationToken {

	/**
	 * 
	 */
	private static final long serialVersionUID = 8512558670587781214L;
	
	private final String puid;
	private final Object principal;
	
	// used for returning to Spring Security after being
	//authenticated
	public WwpassAuthenticationToken(Object principal, String puid, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.puid = puid;
		this.principal = principal;
	}
	
	public String getPuid() {
		return this.puid;
	}
	public Object getCredentials() {
		return null;
	}
	public Object getPrincipal() {
		return this.principal;
	}
}
