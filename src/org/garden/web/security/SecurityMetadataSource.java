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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.garden.sysadmin.dao.model.SysResource;
import org.garden.sysadmin.dao.model.SysRole;
import org.garden.sysadmin.service.SystemService;
import org.garden.utils.CacheUtils;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;

/**
 * SecurityMetadataSource.java
 * 
 * 加载所有"资源-操作"与"权限"的对应关系
 * 
 * @author Garden
 * create on 2014年9月23日 上午10:30:08
 */
public class SecurityMetadataSource implements
FilterInvocationSecurityMetadataSource {
	public static final String DEFAULT_ROLE = "";  // 若url无设置访问权限
	public static final String INVALIDE_RESOURCE = "SEC_INVALID_RESOURCE";  // 若url无设置访问权限
	
	private Log log = LogFactory.getLog(SecurityMetadataSource.class);
	// 资源操作缓存
	//private static Map<String, List<ConfigAttribute>> resourceRoleMap = null;
	private static final String CACHE_KEY = "role_cache";
	
	private SystemService systemService;
	
	/**
	 * @param systemService the systemService to set
	 */
	public void setSystemService(SystemService systemService) {
		this.systemService = systemService;
	}

	public SecurityMetadataSource(SystemService systemService) {
		this.systemService = systemService;
		loadResourceOperDetails();
	}
	
	/**
	 * 初始化资源缓存，将所有资源
	 */
	private Map<String, List<ConfigAttribute>> loadResourceOperDetails() {	
		Map<String, List<ConfigAttribute>> resourceRoleMap = (Map<String, List<ConfigAttribute>>) CacheUtils.getInstance().get(CACHE_KEY);
		
		if ( resourceRoleMap == null) {
			List<SysResource> sysResources = systemService.getAllResourcesWithRoles();
			
			resourceRoleMap = new HashMap<String, List<ConfigAttribute>>();
			
			for ( SysResource sysResource : sysResources) {
				List<ConfigAttribute> caList = new ArrayList<ConfigAttribute>();
				String url = sysResource.getResourceUrl();
				
				if( sysResource.getStatus().equals("0")) { // 无效资源
					ConfigAttribute ca = new SecurityConfig(INVALIDE_RESOURCE);
					caList.add(ca);
				} else {
					List<SysRole> roles = sysResource.getRoles();
					
					for ( SysRole role : roles) {
						ConfigAttribute ca = new SecurityConfig(role.getRoleCode());
						caList.add(ca);
					}
				}
				
				resourceRoleMap.put(url, caList);
			}
			
			CacheUtils.getInstance().put(CACHE_KEY, resourceRoleMap);
		}
		
		return resourceRoleMap;
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.access.SecurityMetadataSource#getAllConfigAttributes()
	 */
	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		return null;
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.access.SecurityMetadataSource#getAttributes(java.lang.Object)
	 */
	@Override
	public Collection<ConfigAttribute> getAttributes(Object obj)
			throws IllegalArgumentException {
		String requestUrl = ((FilterInvocation) obj).getRequestUrl();
		String requestKey = requestUrl;
		log.debug("requested url : " + requestUrl);
		
		Map<String, List<ConfigAttribute>> resourceRoleMap =  loadResourceOperDetails();
				
		if ( !resourceRoleMap.containsKey(requestKey)) {
			// 取url问号之前的连接作为关键字
			if ( StringUtils.isNotEmpty(requestUrl)
					&& requestUrl.indexOf("?") > -1) {
				requestKey = requestUrl.substring(0, requestUrl.indexOf("?"));
			}
		}
		
		return resourceRoleMap.get(requestKey);
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.access.SecurityMetadataSource#supports(java.lang.Class)
	 */
	@Override
	public boolean supports(Class<?> arg0) {
		return true;
	}

}
