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

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;

/**
 * SecurityFilter.java
 * 过滤用户请求
 *
 * @author Garden
 * create on 2014年9月22日 下午5:18:59
 */
public class SecurityFilter extends AbstractSecurityInterceptor implements
		Filter {

	private FilterInvocationSecurityMetadataSource securityMetadataSource;
	
	
	/**
	 * @param securityMetadataSource the securityMetadataSource to set
	 */
	public void setSecurityMetadataSource(
			FilterInvocationSecurityMetadataSource securityMetadataSource) {
		this.securityMetadataSource = securityMetadataSource;
	}

	/* (non-Javadoc)
	 * @see javax.servlet.Filter#destroy()
	 */
	@Override
	public void destroy() {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {

		FilterInvocation fi = new FilterInvocation(request, response, chain);  
		invoke(fi);
	}


	private void invoke(FilterInvocation fi) throws IOException, ServletException {  
		//object为FilterInvocation对象  
		//核心的InterceptorStatusToken token = super.beforeInvocation(fi);会调用我们定义的accessDecisionManager:decide(Object object)和securityMetadataSource
		//  :getAttributes(Object object)方法。
		//super.beforeInvocation(fi);源码  
		//1.获取请求资源的权限  
		//执行Collection<ConfigAttribute> attributes = SecurityMetadataSource.getAttributes(object);  
		//2.是否拥有权限  
		//this.accessDecisionManager.decide(authenticated, object, attributes);  
		InterceptorStatusToken token = super.beforeInvocation(fi);  
		try {  
			fi.getChain().doFilter(fi.getRequest(), fi.getResponse());  
		} finally {  
			super.afterInvocation(token, null);  
		}  
	}  


	
	/* (non-Javadoc)
	 * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
	 */
	@Override
	public void init(FilterConfig arg0) throws ServletException {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see org.springframework.security.access.intercept.AbstractSecurityInterceptor#getSecureObjectClass()
	 */
	@Override
	public Class<?> getSecureObjectClass() {
		// TODO Auto-generated method stub
		return FilterInvocation.class;
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.access.intercept.AbstractSecurityInterceptor#obtainSecurityMetadataSource()
	 */
	@Override
	public SecurityMetadataSource obtainSecurityMetadataSource() {
		// TODO Auto-generated method stub
		return this.securityMetadataSource;
	}

}
