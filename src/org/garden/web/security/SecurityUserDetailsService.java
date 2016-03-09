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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.garden.sysadmin.dao.model.SysRole;
import org.garden.sysadmin.dao.model.SysUser;
import org.garden.sysadmin.service.SystemService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * AdminUserDetailsService.java
 *
 * @author Garden
 * create on 2014年9月16日 下午5:33:39
 */
public class SecurityUserDetailsService implements UserDetailsService {
	private Log log = LogFactory.getLog(SecurityUserDetailsService.class);
	
	private SystemService systemService;

	/**
	 * @param securityService the securityService to set
	 */
	public void setSystemService(SystemService systemService) {
		this.systemService = systemService;
	}
	
	/* (non-Javadoc)
	 * @see org.springframework.security.core.userdetails.UserDetailsService#loadUserByUsername(java.lang.String)
	 */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserDetails user = null;
		
		try {
			SysUser sysUser = systemService.getSysUserByUserCode(username);
			
			if ( sysUser == null
					|| !sysUser.isValid()) {
				throw new UsernameNotFoundException(username); 
			}

			Collection<GrantedAuthority> grantedAuths = getGrantedAuthorities(sysUser);
			
			boolean enables = true;  
			boolean accountNonExpired = true;  
			boolean credentialsNonExpired = true;  
			boolean accountNonLocked = true; 

			user = new SecurityUser(sysUser.getUserCode(), sysUser.getPassword(), enables, 
					accountNonExpired, credentialsNonExpired, accountNonLocked, grantedAuths, sysUser.getUserCode());
			
		} catch( Exception e) {
			
		}
		
		return user;
	}

	/**
	 * @param sysUser
	 * @return
	 */
	private Collection<GrantedAuthority> getGrantedAuthorities(SysUser sysUser) {
		Set<GrantedAuthority> authSet = new HashSet<GrantedAuthority>();
		
		
//		List<SysResource> sysResources = securityService.getSysResourceByUserCode(sysUser.getUserCode());
		List<SysRole> sysRoles = systemService.getSysRoleByUserCode(sysUser.getUserCode());
		
		for ( SysRole sysRole : sysRoles) {
			authSet.add( new SimpleGrantedAuthority(sysRole.getRoleCode()));
		}
		
		return authSet;
	}

}
