/*
 * Copyright (c) 2004, 2014, Garden Lee. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Oracle or the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */ 
package org.garden.web.security;

import java.util.Collection;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * SecurityAccessDecision.java
 *
 * @author Garden
 * create on 2014年9月24日 下午4:40:27
 */
public class SecurityAccessDecision implements AccessDecisionManager {
	private Log log = LogFactory.getLog(SecurityAccessDecision.class);
	/* (non-Javadoc)
	 * @see org.springframework.security.access.AccessDecisionManager#decide(org.springframework.security.core.Authentication, java.lang.Object, java.util.Collection)
	 */
	@Override
	public void decide(Authentication authentication, Object object,
			Collection<ConfigAttribute> configs) throws AccessDeniedException,
			InsufficientAuthenticationException {
		if ( configs == null) {
			log.warn("doesn't find any roles for this user");
		} else {
			//所请求的资源拥有的权限(一个资源对多个权限)  
			Iterator<ConfigAttribute> iterator = configs.iterator();

			while(iterator.hasNext()) {  
				ConfigAttribute configAttribute = iterator.next();  
				//访问所请求资源所需要的权限  
				String roleCodeOfUrl = configAttribute.getAttribute();  
				log.debug("the ROLE_CODE of the URL is " + roleCodeOfUrl);  
				//用户所拥有的权限authentication  
				for(GrantedAuthority ga : authentication.getAuthorities()) {  
					if(roleCodeOfUrl.equals(ga.getAuthority())) {  
						return;
					}  
				}  
			}
		}

		//没有权限  
		throw new AccessDeniedException("ERROR:403. Request denied");
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.access.AccessDecisionManager#supports(org.springframework.security.access.ConfigAttribute)
	 */
	@Override
	public boolean supports(ConfigAttribute arg0) {
		return true;
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.access.AccessDecisionManager#supports(java.lang.Class)
	 */
	@Override
	public boolean supports(Class<?> arg0) {
		return true;
	}

}
