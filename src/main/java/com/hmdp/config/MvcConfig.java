package com.hmdp.config;


import com.hmdp.utils.LoginInterceptor;

import com.hmdp.utils.RefreshTokenInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class MvcConfig  implements WebMvcConfigurer {
    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    /**
     * order值越小，拦截顺序越高。
     * @param registry
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor( new RefreshTokenInterceptor(stringRedisTemplate)).order(0);

      registry.addInterceptor(new LoginInterceptor()
      ).excludePathPatterns(
              // 放行的路径
              "/shop/**",
              "/shop-type/**",
              "/upload/**",
              "blog/hot",
              "/user/code",
              "/user/login"

      ).order(1);

    }
}
